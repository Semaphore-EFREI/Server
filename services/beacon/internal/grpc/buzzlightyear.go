package grpc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	beaconv1 "semaphore/beacon/beacon/v1"
	"semaphore/beacon/internal/db"
)

const (
	buzzLightyearInvalidSignature = "invalid_signature"
	buzzLightyearReplay           = "proof_replay"
	buzzLightyearReplayPrefix     = "buzzlightyear:proof:"
)

var errProofReplay = errors.New("proof_replay")

func (s *BeaconQueryServer) ValidateBuzzLightyearProof(ctx context.Context, req *beaconv1.ValidateBuzzLightyearProofRequest) (*beaconv1.ValidateBuzzLightyearProofResponse, error) {
	if req.GetBeaconSerialNumber() <= 0 || req.GetSignature() == "" || req.GetStudentId() == "" || req.GetCode() == 0 {
		return nil, status.Error(codes.InvalidArgument, "beacon_serial_number, student_id, code, and signature required")
	}
	serial := strconv.FormatInt(req.GetBeaconSerialNumber(), 10)
	beacon, err := s.store.Queries.GetBeaconBySerial(ctx, serial)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "beacon not found")
		}
		return nil, status.Error(codes.Internal, "beacon lookup failed")
	}
	if !beacon.ClassroomID.Valid {
		return &beaconv1.ValidateBuzzLightyearProofResponse{IsValid: false, ErrorCode: "classroom_not_assigned"}, nil
	}
	key, err := decodeCMACKey(beacon.SignatureKey)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "signature_key_invalid")
	}
	signatureBytes, err := decodeBase64(req.GetSignature())
	if err != nil {
		return &beaconv1.ValidateBuzzLightyearProofResponse{IsValid: false, ErrorCode: buzzLightyearInvalidSignature}, nil
	}

	message := fmt.Sprintf("%d", req.GetCode())
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "signature_key_invalid")
	}
	expected, err := computeCMAC(block, []byte(message))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "signature_key_invalid")
	}
	if subtle.ConstantTimeCompare(signatureBytes, expected) != 1 {
		return &beaconv1.ValidateBuzzLightyearProofResponse{IsValid: false, ErrorCode: buzzLightyearInvalidSignature}, nil
	}

	if err := s.recordBuzzLightyearProof(ctx, req); err != nil {
		if errors.Is(err, errProofReplay) {
			return &beaconv1.ValidateBuzzLightyearProofResponse{IsValid: false, ErrorCode: buzzLightyearReplay}, nil
		}
		return nil, status.Error(codes.Internal, "proof_store_failed")
	}

	if beacon.ID.Valid {
		_ = s.store.Queries.UpdateBeaconLastSeen(ctx, db.UpdateBeaconLastSeenParams{
			ID:         beacon.ID,
			LastSeenAt: pgTime(time.Now().UTC()),
		})
	}

	return &beaconv1.ValidateBuzzLightyearProofResponse{IsValid: true, ClassroomId: uuidString(beacon.ClassroomID)}, nil
}

func (s *BeaconQueryServer) recordBuzzLightyearProof(ctx context.Context, req *beaconv1.ValidateBuzzLightyearProofRequest) error {
	if s.redis == nil {
		return errors.New("redis_unavailable")
	}
	if s.proofReplayTTL <= 0 {
		return errors.New("invalid_replay_ttl")
	}
	key := buzzLightyearProofKey(req)
	ok, err := s.redis.SetNX(ctx, key, "1", s.proofReplayTTL).Result()
	if err != nil {
		return err
	}
	if !ok {
		return errProofReplay
	}
	return nil
}

func buzzLightyearProofKey(req *beaconv1.ValidateBuzzLightyearProofRequest) string {
	payload := fmt.Sprintf("%s:%d", strings.TrimSpace(req.GetStudentId()), req.GetCode())
	hash := sha256.Sum256([]byte(payload))
	return buzzLightyearReplayPrefix + base64.RawURLEncoding.EncodeToString(hash[:])
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func decodeCMACKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty_key")
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return validateAESKey(decoded)
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return validateAESKey(decoded)
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return validateAESKey(decoded)
	}
	if len(value) == 16 || len(value) == 24 || len(value) == 32 {
		return []byte(value), nil
	}
	return nil, errors.New("invalid_key")
}

func validateAESKey(key []byte) ([]byte, error) {
	switch len(key) {
	case 16, 24, 32:
		return key, nil
	default:
		return nil, errors.New("invalid_key_length")
	}
}

func computeCMAC(block cipher.Block, message []byte) ([]byte, error) {
	const blockSize = 16
	if block.BlockSize() != blockSize {
		return nil, errors.New("invalid_block_size")
	}
	k1, k2 := cmacSubkeys(block)
	n := (len(message) + blockSize - 1) / blockSize
	if n == 0 {
		n = 1
	}
	complete := len(message) > 0 && len(message)%blockSize == 0
	var lastBlock []byte
	if complete {
		lastBlock = xorBlock(message[(n-1)*blockSize:], k1)
	} else {
		lastBlock = xorBlock(padBlock(message[(n-1)*blockSize:]), k2)
	}

	x := make([]byte, blockSize)
	y := make([]byte, blockSize)
	for i := 0; i < n-1; i++ {
		copy(y, message[i*blockSize:(i+1)*blockSize])
		xorBlockInPlace(y, x)
		block.Encrypt(x, y)
	}
	copy(y, lastBlock)
	xorBlockInPlace(y, x)
	out := make([]byte, blockSize)
	block.Encrypt(out, y)
	return out, nil
}

func cmacSubkeys(block cipher.Block) ([]byte, []byte) {
	const blockSize = 16
	const rb = 0x87
	zero := make([]byte, blockSize)
	l := make([]byte, blockSize)
	block.Encrypt(l, zero)
	k1 := leftShiftOne(l)
	if l[0]&0x80 != 0 {
		k1[blockSize-1] ^= rb
	}
	k2 := leftShiftOne(k1)
	if k1[0]&0x80 != 0 {
		k2[blockSize-1] ^= rb
	}
	return k1, k2
}

func leftShiftOne(in []byte) []byte {
	out := make([]byte, len(in))
	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = (in[i] << 1) | carry
		carry = (in[i] >> 7) & 1
	}
	return out
}

func padBlock(in []byte) []byte {
	const blockSize = 16
	out := make([]byte, blockSize)
	copy(out, in)
	if len(in) < blockSize {
		out[len(in)] = 0x80
	}
	return out
}

func xorBlock(a, b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	xorBlockInPlace(out, a)
	return out
}

func xorBlockInPlace(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}
