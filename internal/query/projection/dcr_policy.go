package projection

import (
	"context"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	old_handler "github.com/zitadel/zitadel/internal/eventstore/handler"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/repository/org"
	"github.com/zitadel/zitadel/internal/repository/policy"
	"github.com/zitadel/zitadel/internal/zerrors"
)

const (
	DCRPolicyTable = "projections.dcr_policies1"

	DCRPolicyIDCol                              = "id"
	DCRPolicyCreationDateCol                    = "creation_date"
	DCRPolicyChangeDateCol                      = "change_date"
	DCRPolicySequenceCol                        = "sequence"
	DCRPolicyStateCol                           = "state"
	DCRPolicyIsDefaultCol                       = "is_default"
	DCRPolicyAllowedAudiencesCol                = "allowed_audiences"
	DCRPolicyRegistrationAccessTokenLifetimeCol = "registration_access_token_lifetime"
	DCRPolicyResourceOwnerCol                   = "resource_owner"
	DCRPolicyInstanceIDCol                      = "instance_id"
	DCRPolicyOwnerRemovedCol                    = "owner_removed"
)

type dcrPolicyProjection struct{}

func newDCRPolicyProjection(ctx context.Context, config handler.Config) *handler.Handler {
	return handler.NewHandler(ctx, &config, new(dcrPolicyProjection))
}

func (*dcrPolicyProjection) Name() string {
	return DCRPolicyTable
}

func (*dcrPolicyProjection) Init() *old_handler.Check {
	return handler.NewTableCheck(
		handler.NewTable([]*handler.InitColumn{
			handler.NewColumn(DCRPolicyIDCol, handler.ColumnTypeText),
			handler.NewColumn(DCRPolicyCreationDateCol, handler.ColumnTypeTimestamp),
			handler.NewColumn(DCRPolicyChangeDateCol, handler.ColumnTypeTimestamp),
			handler.NewColumn(DCRPolicySequenceCol, handler.ColumnTypeInt64),
			handler.NewColumn(DCRPolicyStateCol, handler.ColumnTypeEnum),
			handler.NewColumn(DCRPolicyIsDefaultCol, handler.ColumnTypeBool, handler.Default(false)),
			handler.NewColumn(DCRPolicyAllowedAudiencesCol, handler.ColumnTypeTextArray, handler.Nullable()),
			// Stored as nanoseconds (BIGINT) for projection-tool portability
			// per cavekit-org-dcr-policy.md R2.
			handler.NewColumn(DCRPolicyRegistrationAccessTokenLifetimeCol, handler.ColumnTypeInt64, handler.Nullable()),
			handler.NewColumn(DCRPolicyResourceOwnerCol, handler.ColumnTypeText),
			handler.NewColumn(DCRPolicyInstanceIDCol, handler.ColumnTypeText),
			handler.NewColumn(DCRPolicyOwnerRemovedCol, handler.ColumnTypeBool, handler.Default(false)),
		},
			handler.NewPrimaryKey(DCRPolicyInstanceIDCol, DCRPolicyIDCol),
			handler.WithIndex(handler.NewIndex("dcr_policies_instance_resource_owner",
				[]string{DCRPolicyInstanceIDCol, DCRPolicyResourceOwnerCol})),
		),
	)
}

func (p *dcrPolicyProjection) Reducers() []handler.AggregateReducer {
	return []handler.AggregateReducer{
		{
			Aggregate: org.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  org.OrgDCRPolicyAddedEventType,
					Reduce: p.reduceAdded,
				},
				{
					Event:  org.OrgDCRPolicyChangedEventType,
					Reduce: p.reduceChanged,
				},
				{
					Event:  org.OrgDCRPolicyRemovedEventType,
					Reduce: p.reduceRemoved,
				},
				{
					Event:  org.OrgRemovedEventType,
					Reduce: p.reduceOwnerRemoved,
				},
			},
		},
		{
			Aggregate: instance.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  instance.InstanceDCRPolicyAddedEventType,
					Reduce: p.reduceAdded,
				},
				{
					Event:  instance.InstanceDCRPolicyChangedEventType,
					Reduce: p.reduceChanged,
				},
				{
					Event:  instance.InstanceRemovedEventType,
					Reduce: reduceInstanceRemovedHelper(DCRPolicyInstanceIDCol),
				},
			},
		},
	}
}

func (p *dcrPolicyProjection) reduceAdded(event eventstore.Event) (*handler.Statement, error) {
	var policyEvent policy.DCRPolicyAddedEvent
	var isDefault bool
	switch e := event.(type) {
	case *org.OrgDCRPolicyAddedEvent:
		policyEvent = e.DCRPolicyAddedEvent
		isDefault = false
	case *instance.InstanceDCRPolicyAddedEvent:
		policyEvent = e.DCRPolicyAddedEvent
		isDefault = true
	default:
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-DcRA1", "reduce.wrong.event.type %v",
			[]eventstore.EventType{org.OrgDCRPolicyAddedEventType, instance.InstanceDCRPolicyAddedEventType})
	}

	cols := []handler.Column{
		handler.NewCol(DCRPolicyCreationDateCol, policyEvent.CreationDate()),
		handler.NewCol(DCRPolicyChangeDateCol, policyEvent.CreationDate()),
		handler.NewCol(DCRPolicySequenceCol, policyEvent.Sequence()),
		handler.NewCol(DCRPolicyIDCol, policyEvent.Aggregate().ID),
		handler.NewCol(DCRPolicyStateCol, domain.PolicyStateActive),
		handler.NewCol(DCRPolicyIsDefaultCol, isDefault),
		handler.NewCol(DCRPolicyResourceOwnerCol, policyEvent.Aggregate().ResourceOwner),
		handler.NewCol(DCRPolicyInstanceIDCol, policyEvent.Aggregate().InstanceID),
	}
	if policyEvent.AllowedAudiences != nil {
		cols = append(cols, handler.NewCol(DCRPolicyAllowedAudiencesCol,
			database.TextArray[string](*policyEvent.AllowedAudiences)))
	}
	if policyEvent.RegistrationAccessTokenLifetime != nil {
		cols = append(cols, handler.NewCol(DCRPolicyRegistrationAccessTokenLifetimeCol,
			policyEvent.RegistrationAccessTokenLifetime.Nanoseconds()))
	}
	return handler.NewCreateStatement(&policyEvent, cols), nil
}

func (p *dcrPolicyProjection) reduceChanged(event eventstore.Event) (*handler.Statement, error) {
	var policyEvent policy.DCRPolicyChangedEvent
	switch e := event.(type) {
	case *org.OrgDCRPolicyChangedEvent:
		policyEvent = e.DCRPolicyChangedEvent
	case *instance.InstanceDCRPolicyChangedEvent:
		policyEvent = e.DCRPolicyChangedEvent
	default:
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-DcRC1", "reduce.wrong.event.type %v",
			[]eventstore.EventType{org.OrgDCRPolicyChangedEventType, instance.InstanceDCRPolicyChangedEventType})
	}

	cols := []handler.Column{
		handler.NewCol(DCRPolicyChangeDateCol, policyEvent.CreationDate()),
		handler.NewCol(DCRPolicySequenceCol, policyEvent.Sequence()),
	}
	if policyEvent.AllowedAudiences != nil {
		cols = append(cols, handler.NewCol(DCRPolicyAllowedAudiencesCol,
			database.TextArray[string](*policyEvent.AllowedAudiences)))
	}
	if policyEvent.RegistrationAccessTokenLifetime != nil {
		cols = append(cols, handler.NewCol(DCRPolicyRegistrationAccessTokenLifetimeCol,
			policyEvent.RegistrationAccessTokenLifetime.Nanoseconds()))
	}
	return handler.NewUpdateStatement(
		&policyEvent,
		cols,
		[]handler.Condition{
			handler.NewCond(DCRPolicyIDCol, policyEvent.Aggregate().ID),
			handler.NewCond(DCRPolicyInstanceIDCol, policyEvent.Aggregate().InstanceID),
		}), nil
}

func (p *dcrPolicyProjection) reduceRemoved(event eventstore.Event) (*handler.Statement, error) {
	policyEvent, ok := event.(*org.OrgDCRPolicyRemovedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-DcRR1", "reduce.wrong.event.type %s",
			org.OrgDCRPolicyRemovedEventType)
	}
	return handler.NewDeleteStatement(
		policyEvent,
		[]handler.Condition{
			handler.NewCond(DCRPolicyIDCol, policyEvent.Aggregate().ID),
			handler.NewCond(DCRPolicyInstanceIDCol, policyEvent.Aggregate().InstanceID),
		}), nil
}

// reduceOwnerRemoved cascades OrgRemoved into a per-row owner_removed=TRUE
// flag (matching the domain_policy precedent: org rows live but are filtered
// out of queries until the GC reaper deletes them).
func (p *dcrPolicyProjection) reduceOwnerRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, ok := event.(*org.OrgRemovedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-DcROR1", "reduce.wrong.event.type %s", org.OrgRemovedEventType)
	}
	return handler.NewUpdateStatement(
		e,
		[]handler.Column{
			handler.NewCol(DCRPolicyChangeDateCol, e.CreationDate()),
			handler.NewCol(DCRPolicySequenceCol, e.Sequence()),
			handler.NewCol(DCRPolicyOwnerRemovedCol, true),
		},
		[]handler.Condition{
			handler.NewCond(DCRPolicyInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(DCRPolicyResourceOwnerCol, e.Aggregate().ID),
		}), nil
}
