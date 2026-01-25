package grpc

import "testing"

func TestRequireUUID(t *testing.T) {
	value, err := requireUUID("11111111-1111-1111-1111-111111111111", "school_id")
	if err != nil {
		t.Fatalf("expected valid uuid, got error %v", err)
	}
	if !value.Valid {
		t.Fatalf("expected valid pgtype.UUID")
	}

	_, err = requireUUID("invalid", "school_id")
	if err == nil {
		t.Fatalf("expected error for invalid uuid")
	}
}

func TestUUIDStringRoundTrip(t *testing.T) {
	parsed, err := parseUUID("22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if got := uuidString(parsed); got != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("expected round trip, got %s", got)
	}
}
