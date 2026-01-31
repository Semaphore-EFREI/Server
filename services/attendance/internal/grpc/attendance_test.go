package grpc

import (
	"testing"

	attendancev1 "semaphore/attendance/attendance/v1"
	"semaphore/attendance/internal/db"
)

func TestStatusToGRPC(t *testing.T) {
	cases := map[db.SignatureStatus]attendancev1.SignatureStatus{
		"signed":  attendancev1.SignatureStatus_SIGNATURE_STATUS_PENDING,
		"present": attendancev1.SignatureStatus_SIGNATURE_STATUS_ACCEPTED,
		"absent":  attendancev1.SignatureStatus_SIGNATURE_STATUS_REFUSED,
		"late":    attendancev1.SignatureStatus_SIGNATURE_STATUS_LATE,
	}
	for status, expected := range cases {
		if got := statusToGRPC(status); got != expected {
			t.Fatalf("status %s expected %v got %v", status, expected, got)
		}
	}
	if got := statusToGRPC("invalid"); got != attendancev1.SignatureStatus_SIGNATURE_STATUS_UNSPECIFIED {
		t.Fatalf("expected unspecified for invalid status")
	}
}

func TestMethodFromGRPC(t *testing.T) {
	cases := map[attendancev1.SignatureMethod]string{
		attendancev1.SignatureMethod_SIGNATURE_METHOD_NFC:        "nfc",
		attendancev1.SignatureMethod_SIGNATURE_METHOD_FLASHLIGHT: "buzzLightyear",
		attendancev1.SignatureMethod_SIGNATURE_METHOD_BEACON:     "beacon",
		attendancev1.SignatureMethod_SIGNATURE_METHOD_TEACHER:    "teacher",
		attendancev1.SignatureMethod_SIGNATURE_METHOD_ADMIN:      "admin",
	}
	for input, expected := range cases {
		method, err := methodFromGRPC(input)
		if err != nil {
			t.Fatalf("method %v should be valid", input)
		}
		if string(method) != expected {
			t.Fatalf("expected %s got %s", expected, method)
		}
	}
	if _, err := methodFromGRPC(attendancev1.SignatureMethod_SIGNATURE_METHOD_UNSPECIFIED); err == nil {
		t.Fatalf("expected error for unspecified method")
	}
	if _, err := methodFromGRPC(attendancev1.SignatureMethod_SIGNATURE_METHOD_QR); err == nil {
		t.Fatalf("expected error for QR method")
	}
}
