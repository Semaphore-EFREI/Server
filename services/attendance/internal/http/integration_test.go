package http_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

type tokenResponse struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type signatureResponse struct {
	ID      string `json:"id"`
	Date    int64  `json:"date"`
	Course  string `json:"course"`
	Status  string `json:"status"`
	Method  string `json:"method"`
	Image   string `json:"image"`
	Student string `json:"student"`
	Teacher string `json:"teacher"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func TestStudentSignatureRules(t *testing.T) {
	if os.Getenv("INTEGRATION_TESTS") != "1" {
		t.Skip("set INTEGRATION_TESTS=1 to run")
	}
	attendanceURL := getenv("ATTENDANCE_HTTP_ADDR", "http://127.0.0.1:8083")
	authURL := getenv("AUTH_HTTP_ADDR", "http://127.0.0.1:8081")

	token := login(t, authURL, "student@demo.local", "dev-password")
	teacherToken := login(t, authURL, "teacher@demo.local", "dev-password")
	courseID := "11111111-1111-1111-1111-111111111114"
	course2ID := "11111111-1111-1111-1111-111111111116"
	studentID := "22222222-2222-2222-2222-222222222223"
	teacherID := "22222222-2222-2222-2222-222222222222"

	// Ensure teacher presence before student signatures.
	_ = createTeacherSignature(t, attendanceURL, teacherToken, map[string]interface{}{
		"date":    time.Date(2026, 1, 25, 9, 0, 0, 0, time.UTC).Unix(),
		"course":  courseID,
		"status":  "present",
		"method":  "self",
		"teacher": teacherID,
		"image":   "dGVzdC1pbWFnZQ==",
	})
	_ = createTeacherSignature(t, attendanceURL, teacherToken, map[string]interface{}{
		"date":    time.Date(2026, 1, 25, 11, 0, 0, 0, time.UTC).Unix(),
		"course":  course2ID,
		"status":  "present",
		"method":  "self",
		"teacher": teacherID,
		"image":   "dGVzdC1pbWFnZQ==",
	})

	onTime := time.Date(2026, 1, 25, 11, 5, 0, 0, time.UTC).Unix()
	late := time.Date(2026, 1, 25, 9, 20, 0, 0, time.UTC).Unix()
	tooEarly := time.Date(2026, 1, 25, 8, 50, 0, 0, time.UTC).Unix()

	// Too early signature should be rejected.
	reqBody := map[string]interface{}{
		"date":    tooEarly,
		"course":  courseID,
		"status":  "signed",
		"method":  "beacon",
		"student": studentID,
	}
	resp, body := doRequest(t, attendanceURL+"/signature", token, "demo-device-1", reqBody)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp.Error != "too_early" {
		t.Fatalf("expected error too_early, got %s", errResp.Error)
	}

	// On-time signature should be accepted with provided status (second course).
	onTimeResp := createSignature(t, attendanceURL, token, "demo-device-1", map[string]interface{}{
		"date":    onTime,
		"course":  course2ID,
		"status":  "signed",
		"method":  "beacon",
		"student": studentID,
	})
	if onTimeResp.Status != "signed" {
		t.Fatalf("expected status signed, got %s", onTimeResp.Status)
	}

	// Late signature should be accepted with status late.
	lateResp := createSignature(t, attendanceURL, token, "demo-device-1", map[string]interface{}{
		"date":    late,
		"course":  courseID,
		"status":  "signed",
		"method":  "beacon",
		"student": studentID,
	})
	if lateResp.Status != "late" {
		t.Fatalf("expected status late, got %s", lateResp.Status)
	}

	// Patch status to present and verify.
	patchBody := map[string]interface{}{"status": "present"}
	patchResp, _ := doRequestWithMethod(t, http.MethodPatch, attendanceURL+"/signature/"+lateResp.ID, token, "demo-device-1", patchBody)
	if patchResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", patchResp.StatusCode)
	}

	getResp, getBody := doRequestWithMethod(t, http.MethodGet, attendanceURL+"/signature/"+lateResp.ID, token, "demo-device-1", nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	var fetched signatureResponse
	if err := json.Unmarshal(getBody, &fetched); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if fetched.Status != "present" {
		t.Fatalf("expected status present, got %s", fetched.Status)
	}
}

func TestTeacherSignatureRules(t *testing.T) {
	if os.Getenv("INTEGRATION_TESTS") != "1" {
		t.Skip("set INTEGRATION_TESTS=1 to run")
	}
	attendanceURL := getenv("ATTENDANCE_HTTP_ADDR", "http://127.0.0.1:8083")
	authURL := getenv("AUTH_HTTP_ADDR", "http://127.0.0.1:8081")

	token := login(t, authURL, "teacher@demo.local", "dev-password")
	courseID := "11111111-1111-1111-1111-111111111114"
	teacherID := "22222222-2222-2222-2222-222222222222"

	onTime := time.Date(2026, 1, 25, 9, 10, 0, 0, time.UTC).Unix()

	// Teacher signature must include image and self teacher id.
	resp := createTeacherSignature(t, attendanceURL, token, map[string]interface{}{
		"date":    onTime,
		"course":  courseID,
		"status":  "signed",
		"method":  "self",
		"teacher": teacherID,
		"image":   "dGVzdC1pbWFnZQ==",
	})
	if resp.Teacher != teacherID {
		t.Fatalf("expected teacher %s, got %s", teacherID, resp.Teacher)
	}

	// Teacher can patch status but not overwrite image with a new value.
	patchBody := map[string]interface{}{"status": "present"}
	patchResp, _ := doRequestWithMethod(t, http.MethodPatch, attendanceURL+"/signature/"+resp.ID, token, "", patchBody)
	if patchResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", patchResp.StatusCode)
	}

	// Validate status updated.
	getResp, getBody := doRequestWithMethod(t, http.MethodGet, attendanceURL+"/signature/"+resp.ID, token, "", nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	var fetched signatureResponse
	if err := json.Unmarshal(getBody, &fetched); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if fetched.Status != "present" {
		t.Fatalf("expected status present, got %s", fetched.Status)
	}
}

func TestAdminSignatureOverrides(t *testing.T) {
	if os.Getenv("INTEGRATION_TESTS") != "1" {
		t.Skip("set INTEGRATION_TESTS=1 to run")
	}
	attendanceURL := getenv("ATTENDANCE_HTTP_ADDR", "http://127.0.0.1:8083")
	authURL := getenv("AUTH_HTTP_ADDR", "http://127.0.0.1:8081")

	adminToken := login(t, authURL, "admin@demo.local", "dev-password")
	studentToken := login(t, authURL, "student@demo.local", "dev-password")
	courseID := "11111111-1111-1111-1111-111111111114"
	studentID := "22222222-2222-2222-2222-222222222223"
	adminID := "22222222-2222-2222-2222-222222222221"

	onTime := time.Date(2026, 1, 25, 9, 7, 0, 0, time.UTC).Unix()

	sig := createSignature(t, attendanceURL, studentToken, "demo-device-1", map[string]interface{}{
		"date":    onTime,
		"course":  courseID,
		"status":  "signed",
		"method":  "beacon",
		"student": studentID,
	})

	patchBody := map[string]interface{}{
		"status":        "absent",
		"administrator": adminID,
	}
	patchResp, _ := doRequestWithMethod(t, http.MethodPatch, attendanceURL+"/signature/"+sig.ID, adminToken, "", patchBody)
	if patchResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", patchResp.StatusCode)
	}

	getResp, getBody := doRequestWithMethod(t, http.MethodGet, attendanceURL+"/signature/"+sig.ID, adminToken, "", nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	var fetched signatureResponse
	if err := json.Unmarshal(getBody, &fetched); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if fetched.Status != "absent" {
		t.Fatalf("expected status absent, got %s", fetched.Status)
	}
}

func login(t *testing.T, authURL, email, password string) string {
	payload := map[string]string{"email": email, "password": password}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	resp, err := http.Post(authURL+"/auth/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if tokens.Token == "" {
		t.Fatalf("missing token")
	}
	return tokens.Token
}

func createSignature(t *testing.T, baseURL, token, deviceID string, payload map[string]interface{}) signatureResponse {
	resp, body := doRequest(t, baseURL+"/signature", token, deviceID, payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var sig signatureResponse
	if err := json.Unmarshal(body, &sig); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if sig.ID == "" {
		t.Fatalf("missing signature id")
	}
	return sig
}

func createTeacherSignature(t *testing.T, baseURL, token string, payload map[string]interface{}) signatureResponse {
	resp, body := doRequestWithMethod(t, http.MethodPost, baseURL+"/signature", token, "", payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var sig signatureResponse
	if err := json.Unmarshal(body, &sig); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if sig.ID == "" {
		t.Fatalf("missing signature id")
	}
	return sig
}

func doRequest(t *testing.T, url, token, deviceID string, payload map[string]interface{}) (*http.Response, []byte) {
	return doRequestWithMethod(t, http.MethodPost, url, token, deviceID, payload)
}

func doRequestWithMethod(t *testing.T, method, url, token, deviceID string, payload map[string]interface{}) (*http.Response, []byte) {
	var bodyBytes []byte
	if payload != nil {
		var err error
		bodyBytes, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if deviceID != "" {
		req.Header.Set("X-Device-ID", deviceID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, body
}

func getenv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
