package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"semaphore/auth-identity/internal/auth"
	"semaphore/auth-identity/internal/config"
	"semaphore/auth-identity/internal/db"
	"semaphore/auth-identity/internal/repository"
)

const (
	adminID   = "22222222-2222-2222-2222-222222222221"
	teacherID = "22222222-2222-2222-2222-222222222222"
	studentID = "22222222-2222-2222-2222-222222222223"
	schoolID  = "11111111-1111-1111-1111-111111111111"
)

func TestStudentTeacherEndpoints(t *testing.T) {
	pool := openTestDB(t)
	if pool == nil {
		return
	}
	defer pool.Close()

	privateKey, publicKey := mustKeyPair(t)
	cfg := config.Config{
		HTTPAddr:       ":0",
		DatabaseURL:    "",
		JWTPrivateKey:  privateKey,
		JWTPublicKey:   publicKey,
		JWTIssuer:      "test-issuer",
		AccessTokenTTL: 15 * time.Minute,
	}
	store := repository.NewStore(pool)
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("server init error: %v", err)
	}
	app := httptest.NewServer(server.Router())
	defer app.Close()

	adminToken := mustToken(t, cfg.JWTPrivateKey, cfg.JWTIssuer, adminID, "admin", schoolID)
	studentToken := mustToken(t, cfg.JWTPrivateKey, cfg.JWTIssuer, studentID, "student", schoolID)
	teacherToken := mustToken(t, cfg.JWTPrivateKey, cfg.JWTIssuer, teacherID, "teacher", schoolID)

	// Admin can list students by school.
	resp := doReq(t, http.MethodGet, app.URL+"/students/"+schoolID+"?limit=5", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Student can get own profile.
	resp = doReq(t, http.MethodGet, app.URL+"/student/"+studentID, studentToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Student cannot access teacher profile.
	resp = doReq(t, http.MethodGet, app.URL+"/teacher/"+teacherID, studentToken, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	// Teacher can access own profile.
	resp = doReq(t, http.MethodGet, app.URL+"/teacher/"+teacherID, teacherToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Admin can list admins by school.
	resp = doReq(t, http.MethodGet, app.URL+"/admins/"+schoolID+"?limit=5", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestCreateStudentTeacher(t *testing.T) {
	pool := openTestDB(t)
	if pool == nil {
		return
	}
	defer pool.Close()

	privateKey, publicKey := mustKeyPair(t)
	cfg := config.Config{
		HTTPAddr:       ":0",
		DatabaseURL:    "",
		JWTPrivateKey:  privateKey,
		JWTPublicKey:   publicKey,
		JWTIssuer:      "test-issuer",
		AccessTokenTTL: 15 * time.Minute,
	}
	store := repository.NewStore(pool)
	server, err := NewServer(cfg, store)
	if err != nil {
		t.Fatalf("server init error: %v", err)
	}
	app := httptest.NewServer(server.Router())
	defer app.Close()

	adminToken := mustToken(t, cfg.JWTPrivateKey, cfg.JWTIssuer, adminID, "admin", schoolID)
	timestamp := time.Now().Unix()

	studentBody := map[string]interface{}{
		"email":         "student." + time.Now().Format("150405") + "@example.local",
		"password":      "dev-password",
		"firstname":     "Test",
		"lastname":      "Student",
		"createdOn":     timestamp,
		"studentNumber": 20250001,
		"school":        schoolID,
	}
	resp := doReq(t, http.MethodPost, app.URL+"/student", adminToken, studentBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	teacherBody := map[string]interface{}{
		"email":     "teacher." + time.Now().Format("150405") + "@example.local",
		"password":  "dev-password",
		"firstname": "Test",
		"lastname":  "Teacher",
		"createdOn": timestamp,
		"school":    schoolID,
	}
	resp = doReq(t, http.MethodPost, app.URL+"/teacher", adminToken, teacherBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	adminBody := map[string]interface{}{
		"email":     "admin." + time.Now().Format("150405") + "@example.local",
		"password":  "dev-password",
		"firstname": "Test",
		"lastname":  "Admin",
		"createdOn": timestamp,
		"role":      "school_admin",
		"school":    schoolID,
	}
	resp = doReq(t, http.MethodPost, app.URL+"/admin", adminToken, adminBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func openTestDB(t *testing.T) *pgxpool.Pool {
	url := os.Getenv("AUTH_IDENTITY_TEST_DB")
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		t.Skip("AUTH_IDENTITY_TEST_DB or DATABASE_URL not set")
		return nil
	}
	pool, err := db.NewPool(context.Background(), url)
	if err != nil {
		t.Skipf("db unavailable: %v", err)
		return nil
	}
	return pool
}

func mustToken(t *testing.T, privateKeyPEM, issuer, userID, userType, schoolID string) string {
	privateKey, err := auth.ParseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		t.Fatalf("key parse error: %v", err)
	}
	token, err := auth.NewAccessToken(privateKey, issuer, 10*time.Minute, auth.Claims{
		UserID:   userID,
		UserType: userType,
		SchoolID: schoolID,
	})
	if err != nil {
		t.Fatalf("token error: %v", err)
	}
	return token
}

func mustKeyPair(t *testing.T) (string, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen error: %v", err)
	}
	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateDER,
	})
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("public key error: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	})
	return string(privatePEM), string(publicPEM)
}

func doReq(t *testing.T, method, url, token string, body interface{}) *http.Response {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode error: %v", err)
		}
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http error: %v", err)
	}
	return resp
}
