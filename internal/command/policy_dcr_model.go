package command

import (
	"time"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/policy"
)

// PolicyDCRWriteModel is the shared write model behind the org and
// instance DCR-policy aggregates. Fields are pointer types so the
// Reduce path can disambiguate "explicitly set to empty" (allow-list
// is empty, lifetime is 0s) from "absent — inherit upper tier"
// (cavekit-org-dcr-policy.md R1 NULL semantics).
type PolicyDCRWriteModel struct {
	eventstore.WriteModel

	AllowedAudiences                *[]string
	RegistrationAccessTokenLifetime *time.Duration
	State                           domain.PolicyState
}

func (wm *PolicyDCRWriteModel) Reduce() error {
	for _, event := range wm.Events {
		switch e := event.(type) {
		case *policy.DCRPolicyAddedEvent:
			if e.AllowedAudiences != nil {
				v := append([]string(nil), (*e.AllowedAudiences)...)
				wm.AllowedAudiences = &v
			}
			if e.RegistrationAccessTokenLifetime != nil {
				v := *e.RegistrationAccessTokenLifetime
				wm.RegistrationAccessTokenLifetime = &v
			}
			wm.State = domain.PolicyStateActive
		case *policy.DCRPolicyChangedEvent:
			if e.AllowedAudiences != nil {
				v := append([]string(nil), (*e.AllowedAudiences)...)
				wm.AllowedAudiences = &v
			}
			if e.RegistrationAccessTokenLifetime != nil {
				v := *e.RegistrationAccessTokenLifetime
				wm.RegistrationAccessTokenLifetime = &v
			}
		case *policy.DCRPolicyRemovedEvent:
			wm.State = domain.PolicyStateRemoved
			wm.AllowedAudiences = nil
			wm.RegistrationAccessTokenLifetime = nil
		}
	}
	return wm.WriteModel.Reduce()
}

// equalAudiences reports whether two pointer-to-slice values represent
// the same allow-list. nil and empty slices are NOT equal — nil means
// "inherit", empty means "explicitly unrestricted at this tier".
func equalAudiences(a, b *[]string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if len(*a) != len(*b) {
		return false
	}
	for i := range *a {
		if (*a)[i] != (*b)[i] {
			return false
		}
	}
	return true
}

func equalLifetime(a, b *time.Duration) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
