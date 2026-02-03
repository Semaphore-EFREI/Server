package grpc

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	beaconv1 "semaphore/beacon/beacon/v1"
	"semaphore/beacon/internal/db"
)

type BeaconQueryServer struct {
	beaconv1.UnimplementedBeaconQueryServiceServer
	store          *db.Store
	redis          *redis.Client
	proofReplayTTL time.Duration
}

func NewBeaconQueryServer(store *db.Store, redisClient *redis.Client, proofReplayTTL time.Duration) *BeaconQueryServer {
	return &BeaconQueryServer{
		store:          store,
		redis:          redisClient,
		proofReplayTTL: proofReplayTTL,
	}
}

func (s *BeaconQueryServer) ListBeaconsByClassroom(ctx context.Context, req *beaconv1.ListBeaconsByClassroomRequest) (*beaconv1.ListBeaconsByClassroomResponse, error) {
	if req.GetClassroomId() == "" {
		return nil, status.Error(codes.InvalidArgument, "classroom_id required")
	}
	classroomUUID, err := uuid.Parse(req.GetClassroomId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid classroom_id")
	}

	rows, err := s.store.Queries.ListBeaconsByClassroom(ctx, pgUUID(classroomUUID))
	if err != nil {
		return nil, status.Error(codes.Internal, "beacon lookup failed")
	}

	beacons := make([]*beaconv1.Beacon, 0, len(rows))
	for _, row := range rows {
		beacons = append(beacons, mapBeacon(row))
	}
	return &beaconv1.ListBeaconsByClassroomResponse{Beacons: beacons}, nil
}

func (s *BeaconQueryServer) ValidateNfcCode(ctx context.Context, req *beaconv1.ValidateNfcCodeRequest) (*beaconv1.ValidateNfcCodeResponse, error) {
	if req.GetBeaconId() == "" || req.GetTotpCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "beacon_id and totp_code required")
	}
	beaconUUID, err := uuid.Parse(req.GetBeaconId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid beacon_id")
	}
	beacon, err := s.store.Queries.GetBeacon(ctx, pgUUID(beaconUUID))
	if err != nil {
		return nil, status.Error(codes.NotFound, "beacon not found")
	}
	if !beacon.ClassroomID.Valid {
		return &beaconv1.ValidateNfcCodeResponse{IsValid: false, ErrorCode: "classroom_not_assigned"}, nil
	}
	if !beacon.TotpKey.Valid || strings.TrimSpace(beacon.TotpKey.String) == "" {
		return &beaconv1.ValidateNfcCodeResponse{IsValid: false, ErrorCode: "totp_key_missing"}, nil
	}
	valid := validateTotpCode(beacon.TotpKey.String, req.GetTotpCode(), time.Now().UTC())
	if !valid {
		return &beaconv1.ValidateNfcCodeResponse{IsValid: false, ErrorCode: "invalid_totp_code"}, nil
	}
	return &beaconv1.ValidateNfcCodeResponse{IsValid: true, ClassroomId: uuidString(beacon.ClassroomID)}, nil
}

func (s *BeaconQueryServer) GetNfcCode(ctx context.Context, req *beaconv1.GetNfcCodeRequest) (*beaconv1.GetNfcCodeResponse, error) {
	if req.GetBeaconId() == "" {
		return nil, status.Error(codes.InvalidArgument, "beacon_id required")
	}
	beaconUUID, err := uuid.Parse(req.GetBeaconId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid beacon_id")
	}
	beacon, err := s.store.Queries.GetBeacon(ctx, pgUUID(beaconUUID))
	if err != nil {
		return nil, status.Error(codes.NotFound, "beacon not found")
	}
	if !beacon.TotpKey.Valid || strings.TrimSpace(beacon.TotpKey.String) == "" {
		return nil, status.Error(codes.FailedPrecondition, "totp_key missing")
	}
	secretBytes, err := decodeTotpSecret(beacon.TotpKey.String)
	if err != nil || len(secretBytes) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "totp_key invalid")
	}
	now := time.Now().UTC()
	fingerprint := sha256.Sum256(secretBytes)
	return &beaconv1.GetNfcCodeResponse{
		TotpCode:          generateTotp(secretBytes, now),
		GeneratedAt:       now.Unix(),
		SecretFingerprint: hex.EncodeToString(fingerprint[:]),
	}, nil
}

func mapBeacon(row db.Beacon) *beaconv1.Beacon {
	serial := int64(0)
	if row.SerialNumber != "" {
		if parsed, err := strconv.ParseInt(row.SerialNumber, 10, 64); err == nil {
			serial = parsed
		}
	}

	resp := &beaconv1.Beacon{
		Id:             uuidString(row.ID),
		SerialNumber:   serial,
		ClassroomId:    uuidString(row.ClassroomID),
		ProgramVersion: row.ProgramVersion.String,
	}
	if !row.ProgramVersion.Valid {
		resp.ProgramVersion = ""
	}
	return resp
}

func uuidString(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuid.UUID(id.Bytes).String()
}

const (
	totpStepSeconds = 5
	totpDigits      = 6
)

func validateTotpCode(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	secretBytes, err := decodeTotpSecret(secret)
	if err != nil || len(secretBytes) == 0 {
		return false
	}
	for offset := -1; offset <= 1; offset++ {
		t := now.Add(time.Duration(offset*totpStepSeconds) * time.Second)
		if generateTotp(secretBytes, t) == code {
			return true
		}
	}
	return false
}

func decodeTotpSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, errors.New("empty_secret")
	}
	if decoded, err := base64.StdEncoding.DecodeString(secret); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(secret); err == nil {
		return decoded, nil
	}
	return nil, errors.New("invalid_secret")
}

func generateTotp(secret []byte, t time.Time) string {
	counter := uint64(t.Unix() / totpStepSeconds)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	mod := int(math.Pow10(totpDigits))
	otp := bin % mod
	return fmt.Sprintf("%0*d", totpDigits, otp)
}

func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}
