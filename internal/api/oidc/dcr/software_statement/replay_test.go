package software_statement

import (
	"context"
	"errors"
	"testing"
	"time"
)

func makeParsedForReplay(jti string, expUnix int64) *Parsed {
	return &Parsed{
		Body: Body{
			Iss: "https://issuer.example",
			Jti: jti,
			Exp: &expUnix,
		},
	}
}

func TestRecordReplay_FirstSightingPasses(t *testing.T) {
	calls := 0
	recorder := func(_ context.Context, iss, jti string, _, _ time.Time) (JTIRecorderResult, error) {
		calls++
		return JTIRecorderInserted, nil
	}
	now := time.Unix(1_700_000_000, 0)
	parsed := makeParsedForReplay("j1", now.Add(time.Hour).Unix())
	err := RecordReplay(context.Background(), parsed, recorder, now, 24*time.Hour)
	if err != nil {
		t.Fatalf("first sighting must pass: %v", err)
	}
	if calls != 1 {
		t.Errorf("recorder calls = %d", calls)
	}
}

func TestRecordReplay_DuplicateRejectsWithReplayKey(t *testing.T) {
	recorder := func(_ context.Context, _, _ string, _, _ time.Time) (JTIRecorderResult, error) {
		return JTIRecorderAlreadySeen, nil
	}
	now := time.Unix(1_700_000_000, 0)
	parsed := makeParsedForReplay("j1", now.Add(time.Hour).Unix())
	err := RecordReplay(context.Background(), parsed, recorder, now, 24*time.Hour)
	if err == nil || err.I18nKey != ReplayKey {
		t.Fatalf("want Replay, got %+v", err)
	}
}

func TestRecordReplay_DBErrorFailsClosed(t *testing.T) {
	recorder := func(_ context.Context, _, _ string, _, _ time.Time) (JTIRecorderResult, error) {
		return 0, errors.New("connection refused")
	}
	now := time.Unix(1_700_000_000, 0)
	parsed := makeParsedForReplay("j1", now.Add(time.Hour).Unix())
	err := RecordReplay(context.Background(), parsed, recorder, now, 24*time.Hour)
	if err == nil || err.I18nKey != InvalidSignatureKey {
		t.Fatalf("want InvalidSignature (fail-closed), got %+v", err)
	}
}

func TestRecordReplay_RetentionAddsToExp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(time.Hour)
	wantExpiresAt := exp.Add(24 * time.Hour)

	var capturedExpiresAt time.Time
	recorder := func(_ context.Context, _, _ string, _, expiresAt time.Time) (JTIRecorderResult, error) {
		capturedExpiresAt = expiresAt
		return JTIRecorderInserted, nil
	}
	parsed := makeParsedForReplay("j1", exp.Unix())
	if err := RecordReplay(context.Background(), parsed, recorder, now, 24*time.Hour); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !capturedExpiresAt.Equal(wantExpiresAt) {
		t.Errorf("expiresAt = %v, want %v (exp + 24h)", capturedExpiresAt, wantExpiresAt)
	}
}

func TestRecordReplay_NilParsedRejected(t *testing.T) {
	err := RecordReplay(context.Background(), nil, nil, time.Now(), 24*time.Hour)
	if err == nil || err.I18nKey != InvalidSignatureKey {
		t.Fatalf("want InvalidSignature, got %+v", err)
	}
}
