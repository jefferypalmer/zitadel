package projection

import (
	"context"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
	old_handler "github.com/zitadel/zitadel/internal/eventstore/handler"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/repository/project"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// IAT projection (cavekit-iat.md R3 / T-019).
//
// Backs the IAT consume command's pre-push read (T-017): the row's
// `revoked`, `expires_at`, and `uses_consumed` fields are checked
// before any event is pushed, and the next free slot index is derived
// from `uses_consumed`. Race safety lives at the eventstore layer via
// the per-slot UniqueConstraint declared on
// project.InitialAccessTokenConsumedEvent — this projection is a
// query-side cache, NOT a serialization point.
//
// Schema choices versus the kit text:
//   - kit specifies `INT[]` for `consumed_slots`; the projection
//     framework's int-array column type is SMALLINT[], reachable via
//     ColumnTypeEnumArray. SMALLINT comfortably holds any reasonable
//     max_uses value (>32767 slots per IAT is not a real workload).
//   - kit specifies `INT NOT NULL` for `max_uses` / `uses_consumed`;
//     the framework offers BIGINT (Int64) but no INT32. Int64 is the
//     idiomatic choice (matches PersonalAccessTokenColumnSequence and
//     other counters).
const (
	InitialAccessTokenProjectionTable = "projections.initial_access_tokens"

	InitialAccessTokenColumnID                         = "id"
	InitialAccessTokenColumnInstanceID                 = "instance_id"
	InitialAccessTokenColumnResourceOwner              = "resource_owner"
	InitialAccessTokenColumnProjectID                  = "project_id"
	InitialAccessTokenColumnTokenHash                  = "token_hash"
	InitialAccessTokenColumnExpiresAt                  = "expires_at"
	InitialAccessTokenColumnMaxUses                    = "max_uses"
	InitialAccessTokenColumnUsesConsumed               = "uses_consumed"
	InitialAccessTokenColumnConsumedSlots              = "consumed_slots"
	InitialAccessTokenColumnAllowedGrantTypes          = "allowed_grant_types"
	InitialAccessTokenColumnAllowedRedirectURIPatterns = "allowed_redirect_uri_patterns"
	InitialAccessTokenColumnRevoked                    = "revoked"
	InitialAccessTokenColumnCreatedAt                  = "created_at"
	InitialAccessTokenColumnChangeDate                 = "change_date"
	InitialAccessTokenColumnSequence                   = "sequence"
)

type initialAccessTokenProjection struct{}

func newInitialAccessTokenProjection(ctx context.Context, config handler.Config) *handler.Handler {
	return handler.NewHandler(ctx, &config, new(initialAccessTokenProjection))
}

func (*initialAccessTokenProjection) Name() string {
	return InitialAccessTokenProjectionTable
}

func (*initialAccessTokenProjection) Init() *old_handler.Check {
	return handler.NewTableCheck(
		handler.NewTable([]*handler.InitColumn{
			handler.NewColumn(InitialAccessTokenColumnID, handler.ColumnTypeText),
			handler.NewColumn(InitialAccessTokenColumnInstanceID, handler.ColumnTypeText),
			handler.NewColumn(InitialAccessTokenColumnResourceOwner, handler.ColumnTypeText),
			handler.NewColumn(InitialAccessTokenColumnProjectID, handler.ColumnTypeText),
			handler.NewColumn(InitialAccessTokenColumnTokenHash, handler.ColumnTypeText),
			handler.NewColumn(InitialAccessTokenColumnExpiresAt, handler.ColumnTypeTimestamp, handler.Nullable()),
			handler.NewColumn(InitialAccessTokenColumnMaxUses, handler.ColumnTypeInt64),
			handler.NewColumn(InitialAccessTokenColumnUsesConsumed, handler.ColumnTypeInt64, handler.Default(0)),
			handler.NewColumn(InitialAccessTokenColumnConsumedSlots, handler.ColumnTypeEnumArray, handler.Default("{}")),
			handler.NewColumn(InitialAccessTokenColumnAllowedGrantTypes, handler.ColumnTypeTextArray, handler.Nullable()),
			handler.NewColumn(InitialAccessTokenColumnAllowedRedirectURIPatterns, handler.ColumnTypeTextArray, handler.Nullable()),
			handler.NewColumn(InitialAccessTokenColumnRevoked, handler.ColumnTypeBool, handler.Default(false)),
			handler.NewColumn(InitialAccessTokenColumnCreatedAt, handler.ColumnTypeTimestamp),
			handler.NewColumn(InitialAccessTokenColumnChangeDate, handler.ColumnTypeTimestamp),
			handler.NewColumn(InitialAccessTokenColumnSequence, handler.ColumnTypeInt64),
		},
			// Composite PK on (instance_id, id) matches the
			// PersonalAccessTokenProjection convention so cross-instance
			// id collisions cannot occur.
			handler.NewPrimaryKey(InitialAccessTokenColumnInstanceID, InitialAccessTokenColumnID),
			handler.WithIndex(handler.NewIndex("instance_project", []string{InitialAccessTokenColumnInstanceID, InitialAccessTokenColumnProjectID})),
			handler.WithIndex(handler.NewIndex("token_hash", []string{InitialAccessTokenColumnTokenHash})),
		),
	)
}

func (p *initialAccessTokenProjection) Reducers() []handler.AggregateReducer {
	return []handler.AggregateReducer{
		{
			Aggregate: project.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  project.InitialAccessTokenAddedType,
					Reduce: p.reduceAdded,
				},
				{
					Event:  project.InitialAccessTokenConsumedType,
					Reduce: p.reduceConsumed,
				},
				{
					Event:  project.InitialAccessTokenRevokedType,
					Reduce: p.reduceRevoked,
				},
				{
					Event:  project.ProjectRemovedType,
					Reduce: p.reduceProjectRemoved,
				},
			},
		},
		{
			Aggregate: instance.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  instance.InstanceRemovedEventType,
					Reduce: reduceInstanceRemovedHelper(InitialAccessTokenColumnInstanceID),
				},
			},
		},
	}
}

func (p *initialAccessTokenProjection) reduceAdded(event eventstore.Event) (*handler.Statement, error) {
	e, ok := event.(*project.InitialAccessTokenAddedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-IATa1", "reduce.wrong.event.type %s", project.InitialAccessTokenAddedType)
	}
	cols := []handler.Column{
		handler.NewCol(InitialAccessTokenColumnID, e.ID),
		handler.NewCol(InitialAccessTokenColumnInstanceID, e.Aggregate().InstanceID),
		handler.NewCol(InitialAccessTokenColumnResourceOwner, e.Aggregate().ResourceOwner),
		handler.NewCol(InitialAccessTokenColumnProjectID, e.ProjectID),
		handler.NewCol(InitialAccessTokenColumnTokenHash, e.Hash),
		handler.NewCol(InitialAccessTokenColumnMaxUses, int64(e.MaxUses)),
		handler.NewCol(InitialAccessTokenColumnUsesConsumed, int64(0)),
		handler.NewCol(InitialAccessTokenColumnConsumedSlots, database.NumberArray[int16]{}),
		handler.NewCol(InitialAccessTokenColumnAllowedGrantTypes, database.TextArray[string](e.AllowedGrantTypes)),
		handler.NewCol(InitialAccessTokenColumnAllowedRedirectURIPatterns, database.TextArray[string](e.AllowedRedirectURIPatterns)),
		handler.NewCol(InitialAccessTokenColumnRevoked, false),
		handler.NewCol(InitialAccessTokenColumnCreatedAt, e.CreationDate()),
		handler.NewCol(InitialAccessTokenColumnChangeDate, e.CreationDate()),
		handler.NewCol(InitialAccessTokenColumnSequence, e.Sequence()),
	}
	if e.ExpiresAt != nil {
		cols = append(cols, handler.NewCol(InitialAccessTokenColumnExpiresAt, *e.ExpiresAt))
	}
	return handler.NewCreateStatement(e, cols), nil
}

func (p *initialAccessTokenProjection) reduceConsumed(event eventstore.Event) (*handler.Statement, error) {
	e, ok := event.(*project.InitialAccessTokenConsumedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-IATc1", "reduce.wrong.event.type %s", project.InitialAccessTokenConsumedType)
	}
	return handler.NewUpdateStatement(
		e,
		[]handler.Column{
			handler.NewCol(InitialAccessTokenColumnChangeDate, e.CreationDate()),
			handler.NewCol(InitialAccessTokenColumnSequence, e.Sequence()),
			handler.NewIncrementCol(InitialAccessTokenColumnUsesConsumed, int64(1)),
			handler.NewArrayAppendCol(InitialAccessTokenColumnConsumedSlots, int16(e.UseIndex)),
		},
		[]handler.Condition{
			handler.NewCond(InitialAccessTokenColumnID, e.ID),
			handler.NewCond(InitialAccessTokenColumnInstanceID, e.Aggregate().InstanceID),
		},
	), nil
}

func (p *initialAccessTokenProjection) reduceRevoked(event eventstore.Event) (*handler.Statement, error) {
	e, ok := event.(*project.InitialAccessTokenRevokedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-IATr1", "reduce.wrong.event.type %s", project.InitialAccessTokenRevokedType)
	}
	return handler.NewUpdateStatement(
		e,
		[]handler.Column{
			handler.NewCol(InitialAccessTokenColumnChangeDate, e.CreationDate()),
			handler.NewCol(InitialAccessTokenColumnSequence, e.Sequence()),
			handler.NewCol(InitialAccessTokenColumnRevoked, true),
		},
		[]handler.Condition{
			handler.NewCond(InitialAccessTokenColumnID, e.ID),
			handler.NewCond(InitialAccessTokenColumnInstanceID, e.Aggregate().InstanceID),
		},
	), nil
}

// reduceProjectRemoved drops every IAT whose project aggregate was
// deleted. Mirrors the org-removed cleanup pattern from
// PersonalAccessTokenProjection — keeps the projection from holding
// dangling rows after a project soft/hard delete.
func (p *initialAccessTokenProjection) reduceProjectRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, ok := event.(*project.ProjectRemovedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-IATp1", "reduce.wrong.event.type %s", project.ProjectRemovedType)
	}
	return handler.NewDeleteStatement(
		e,
		[]handler.Condition{
			handler.NewCond(InitialAccessTokenColumnInstanceID, e.Aggregate().InstanceID),
			handler.NewCond(InitialAccessTokenColumnProjectID, e.Aggregate().ID),
		},
	), nil
}
