package record

import (
	"reflect"
	"testing"
)

func TestRecord_Normalize(t *testing.T) {
	tests := []struct {
		name   string
		record AccessLog
		want   *AccessLog
	}{{
		name: "headers with certain keys should be redacted",
		record: AccessLog{
			RequestHeaders: map[string][]string{
				"authorization":             {"AValue"},
				"grpcgateway-authorization": {"AValue"},
				"cookie":                    {"AValue"},
				"grpcgateway-cookie":        {"AValue"},
			}, ResponseHeaders: map[string][]string{
				"set-cookie": {"AValue"},
			},
		},
		want: &AccessLog{
			RequestHeaders: map[string][]string{
				"authorization":             {"[REDACTED]"},
				"grpcgateway-authorization": {"[REDACTED]"},
				"cookie":                    {"[REDACTED]"},
				"grpcgateway-cookie":        {"[REDACTED]"},
			}, ResponseHeaders: map[string][]string{
				"set-cookie": {"[REDACTED]"},
			},
		},
	}, {
		name: "header keys should be lower cased",
		record: AccessLog{
			RequestHeaders:  map[string][]string{"AKey": {"AValue"}},
			ResponseHeaders: map[string][]string{"AKey": {"AValue"}}},
		want: &AccessLog{
			RequestHeaders:  map[string][]string{"akey": {"AValue"}},
			ResponseHeaders: map[string][]string{"akey": {"AValue"}}},
	}, {
		name: "an already prune record should stay unchanged",
		record: AccessLog{
			RequestURL: "https://my.zitadel.cloud/",
			RequestHeaders: map[string][]string{
				"authorization": {"[REDACTED]"},
			},
			ResponseHeaders: map[string][]string{},
		},
		want: &AccessLog{
			RequestURL: "https://my.zitadel.cloud/",
			RequestHeaders: map[string][]string{
				"authorization": {"[REDACTED]"},
			},
			ResponseHeaders: map[string][]string{},
		},
	}, {
		// cavekit-security-hardening.md R3 / T-063 audit pin: an IAT-
		// shaped Bearer in the Authorization header MUST be redacted by
		// AccessLog.Normalize. The literal `zdiat_<id>.<random>` shape
		// from cavekit-iat.md R5 is asserted explicitly so a future
		// regression that disables redaction (or excludes Authorization
		// from the redact list) surfaces here in addition to the
		// generic "AValue" case above. The IAT-shaped value is also
		// matched by the cavekit-security-hardening.md R3 amendment
		// regex `zdiat_[^\s"',]+` for downstream wrapper-based
		// redaction (T-061); pinning at the logstore layer is
		// defence-in-depth.
		name: "T-063: IAT-shaped Bearer in Authorization MUST be redacted",
		record: AccessLog{
			RequestHeaders: map[string][]string{
				"authorization":             {"Bearer zdiat_kj3h9.abcDEFghi1234567890_-XYZabcDEFghi1234567890_-Xa"},
				"grpcgateway-authorization": {"Bearer zdiat_kj3h9.abcDEFghi1234567890_-XYZabcDEFghi1234567890_-Xa"},
			},
			ResponseHeaders: map[string][]string{},
		},
		want: &AccessLog{
			RequestHeaders: map[string][]string{
				"authorization":             {"[REDACTED]"},
				"grpcgateway-authorization": {"[REDACTED]"},
			},
			ResponseHeaders: map[string][]string{},
		},
	}, {
		// T-063 audit pin: a RAT-shaped Bearer (zdrat_ prefix from RFC
		// 7592 manage path) is the same redaction surface — same
		// header key, same Authorization channel.
		name: "T-063: RAT-shaped Bearer in Authorization MUST be redacted",
		record: AccessLog{
			RequestHeaders: map[string][]string{
				"authorization": {"Bearer zdrat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			},
			ResponseHeaders: map[string][]string{},
		},
		want: &AccessLog{
			RequestHeaders: map[string][]string{
				"authorization": {"[REDACTED]"},
			},
			ResponseHeaders: map[string][]string{},
		},
	}, {
		name: "empty record should stay empty",
		record: AccessLog{
			RequestHeaders:  map[string][]string{},
			ResponseHeaders: map[string][]string{},
		},
		want: &AccessLog{
			RequestHeaders:  map[string][]string{},
			ResponseHeaders: map[string][]string{},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want.normalized = true
			if got := tt.record.Normalize(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Normalize() = %v, want %v", got, tt.want)
			}
		})
	}
}
