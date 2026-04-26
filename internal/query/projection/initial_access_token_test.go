package projection

import (
	"testing"
	"time"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/repository/project"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// args matches the existing projection-test pattern (see
// user_personal_access_token_test.go) so future test edits don't have
// to learn a new shape.
type iatArgs struct {
	event func(t *testing.T) eventstore.Event
}

// TestInitialAccessTokenProjection_reduces pins the cavekit-iat.md R3
// reducers — one INSERT, two UPDATEs (consume + revoke), and the
// project-removed cleanup. Wire-shape (column order, condition order,
// argument types) is part of the contract because the consume command
// (T-017) relies on the row layout.
func TestInitialAccessTokenProjection_reduces(t *testing.T) {
	expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name   string
		args   iatArgs
		reduce func(event eventstore.Event) (*handler.Statement, error)
		want   wantReduce
	}{
		{
			name: "reduceAdded — INSERT row with all metadata + zero-value uses_consumed",
			args: iatArgs{
				event: getEvent(testEvent(
					project.InitialAccessTokenAddedType,
					project.AggregateType,
					[]byte(`{"id":"iat-1","hash":"$argon2id$...","max_uses":3,"expires_at":"2030-01-02T03:04:05Z","project_id":"proj-1","allowed_grant_types":["authorization_code"],"allowed_redirect_uri_patterns":["https://*.example.com/cb"],"description":"test"}`),
				), project.InitialAccessTokenAddedEventMapper),
			},
			reduce: (&initialAccessTokenProjection{}).reduceAdded,
			want: wantReduce{
				aggregateType: project.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "INSERT INTO projections.initial_access_tokens (id, instance_id, resource_owner, project_id, token_hash, max_uses, uses_consumed, consumed_slots, allowed_grant_types, allowed_redirect_uri_patterns, revoked, created_at, change_date, sequence, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
							expectedArgs: []interface{}{
								"iat-1",
								"instance-id",
								"ro-id",
								"proj-1",
								"$argon2id$...",
								int64(3),
								int64(0),
								database.NumberArray[int16]{},
								database.TextArray[string]{"authorization_code"},
								database.TextArray[string]{"https://*.example.com/cb"},
								false,
								anyArg{},
								anyArg{},
								uint64(15),
								expiry,
							},
						},
					},
				},
			},
		},
		{
			name: "reduceAdded — null expires_at column is omitted when ExpiresAt is nil",
			args: iatArgs{
				event: getEvent(testEvent(
					project.InitialAccessTokenAddedType,
					project.AggregateType,
					[]byte(`{"id":"iat-2","hash":"h","max_uses":0,"project_id":"proj-1"}`),
				), project.InitialAccessTokenAddedEventMapper),
			},
			reduce: (&initialAccessTokenProjection{}).reduceAdded,
			want: wantReduce{
				aggregateType: project.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "INSERT INTO projections.initial_access_tokens (id, instance_id, resource_owner, project_id, token_hash, max_uses, uses_consumed, consumed_slots, allowed_grant_types, allowed_redirect_uri_patterns, revoked, created_at, change_date, sequence) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
							expectedArgs: []interface{}{
								"iat-2",
								"instance-id",
								"ro-id",
								"proj-1",
								"h",
								int64(0),
								int64(0),
								database.NumberArray[int16]{},
								database.TextArray[string](nil),
								database.TextArray[string](nil),
								false,
								anyArg{},
								anyArg{},
								uint64(15),
							},
						},
					},
				},
			},
		},
		{
			name: "reduceConsumed — increments uses_consumed and appends use_index",
			args: iatArgs{
				event: getEvent(testEvent(
					project.InitialAccessTokenConsumedType,
					project.AggregateType,
					[]byte(`{"id":"iat-1","use_index":2}`),
				), project.InitialAccessTokenConsumedEventMapper),
			},
			reduce: (&initialAccessTokenProjection{}).reduceConsumed,
			want: wantReduce{
				aggregateType: project.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "UPDATE projections.initial_access_tokens SET (change_date, sequence, uses_consumed, consumed_slots) = ($1, $2, uses_consumed + $3, array_append(consumed_slots, $4)) WHERE (id = $5) AND (instance_id = $6)",
							expectedArgs: []interface{}{
								anyArg{},
								uint64(15),
								int64(1),
								int16(2),
								"iat-1",
								"instance-id",
							},
						},
					},
				},
			},
		},
		{
			name: "reduceRevoked — flips revoked=true",
			args: iatArgs{
				event: getEvent(testEvent(
					project.InitialAccessTokenRevokedType,
					project.AggregateType,
					[]byte(`{"id":"iat-1"}`),
				), project.InitialAccessTokenRevokedEventMapper),
			},
			reduce: (&initialAccessTokenProjection{}).reduceRevoked,
			want: wantReduce{
				aggregateType: project.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "UPDATE projections.initial_access_tokens SET (change_date, sequence, revoked) = ($1, $2, $3) WHERE (id = $4) AND (instance_id = $5)",
							expectedArgs: []interface{}{
								anyArg{},
								uint64(15),
								true,
								"iat-1",
								"instance-id",
							},
						},
					},
				},
			},
		},
		{
			name: "reduceProjectRemoved — drops every IAT for the deleted project",
			args: iatArgs{
				event: getEvent(testEvent(
					project.ProjectRemovedType,
					project.AggregateType,
					nil,
				), project.ProjectRemovedEventMapper),
			},
			reduce: (&initialAccessTokenProjection{}).reduceProjectRemoved,
			want: wantReduce{
				aggregateType: project.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "DELETE FROM projections.initial_access_tokens WHERE (instance_id = $1) AND (project_id = $2)",
							expectedArgs: []interface{}{
								"instance-id",
								"agg-id",
							},
						},
					},
				},
			},
		},
		{
			name: "reduceInstanceRemoved — drops every IAT in the removed instance",
			args: iatArgs{
				event: getEvent(testEvent(
					instance.InstanceRemovedEventType,
					instance.AggregateType,
					nil,
				), instance.InstanceRemovedEventMapper),
			},
			reduce: reduceInstanceRemovedHelper(InitialAccessTokenColumnInstanceID),
			want: wantReduce{
				aggregateType: instance.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "DELETE FROM projections.initial_access_tokens WHERE (instance_id = $1)",
							expectedArgs: []interface{}{
								"agg-id",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := baseEvent(t)
			got, err := tt.reduce(event)
			// Reducers return InvalidArgument when the event isn't of
			// the expected concrete type; the project-removed and
			// instance-removed reducers also follow this contract.
			if ok := zerrors.IsErrorInvalidArgument(err); !ok {
				t.Errorf("expected invalid-argument on base event mismatch, got err=%v stmt=%v", err, got)
			}

			event = tt.args.event(t)
			got, err = tt.reduce(event)
			assertReduce(t, got, err, InitialAccessTokenProjectionTable, tt.want)
		})
	}
}
