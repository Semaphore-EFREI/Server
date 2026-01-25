package http

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	academicsv1 "semaphore/academics/academics/v1"
)

func TestNormalizeStatus(t *testing.T) {
	valid := []string{"signed", "present", "absent", "late", "excused", "invalid"}
	for _, status := range valid {
		if _, err := normalizeStatus(status); err != nil {
			t.Fatalf("expected status %s to be valid", status)
		}
	}
	if _, err := normalizeStatus("unknown"); err == nil {
		t.Fatalf("expected invalid status to error")
	}
}

func TestNormalizeMethod(t *testing.T) {
	cases := map[string]string{
		"flash":         "buzzLightyear",
		"qrcode":        "qrCode",
		"nfc":           "nfc",
		"beacon":        "beacon",
		"buzzLightyear": "buzzLightyear",
		"qrCode":        "qrCode",
		"teacher":       "teacher",
		"web":           "web",
		"self":          "self",
		"admin":         "admin",
	}
	for input, expect := range cases {
		method, err := normalizeMethod(input)
		if err != nil {
			t.Fatalf("expected method %s to be valid", input)
		}
		if string(method) != expect {
			t.Fatalf("expected %s, got %s", expect, method)
		}
	}
	if _, err := normalizeMethod(""); err == nil {
		t.Fatalf("expected empty method to error")
	}
}

func TestValidateTiming(t *testing.T) {
	start := time.Date(2026, 1, 25, 9, 0, 0, 0, time.UTC)
	end := time.Date(2026, 1, 25, 10, 0, 0, 0, time.UTC)
	course := &academicsv1.Course{
		StartAt:                      timestamppb.New(start),
		EndAt:                        timestamppb.New(end),
		SignatureClosingDelayMinutes: 15,
		SignatureClosed:              false,
	}

	if _, errCode := validateTiming(course, start.Add(-time.Minute)); errCode != "too_early" {
		t.Fatalf("expected too_early, got %s", errCode)
	}
	if _, errCode := validateTiming(course, end.Add(time.Minute)); errCode != "course_ended" {
		t.Fatalf("expected course_ended, got %s", errCode)
	}
	status, errCode := validateTiming(course, start.Add(20*time.Minute))
	if errCode != "" || status != "late" {
		t.Fatalf("expected late with no error, got status=%s err=%s", status, errCode)
	}
	status, errCode = validateTiming(course, start.Add(5*time.Minute))
	if errCode != "" || status != "" {
		t.Fatalf("expected on-time with no status, got status=%s err=%s", status, errCode)
	}

	course.SignatureClosed = true
	if _, errCode := validateTiming(course, start.Add(1*time.Minute)); errCode != "signature_closed" {
		t.Fatalf("expected signature_closed, got %s", errCode)
	}
}
