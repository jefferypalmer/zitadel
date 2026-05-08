package query

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/zitadel/zitadel/internal/domain"
)

var (
	prepareDCRDefaultProjectStmt = `SELECT projections.projects4.state,` +
		` projections.projects4.resource_owner` +
		` FROM projections.projects4`
	prepareDCRDefaultProjectCols = []string{"state", "resource_owner"}

	prepareDCRDefaultOrgStmt = `SELECT projections.orgs1.org_state` +
		` FROM projections.orgs1`
	prepareDCRDefaultOrgCols = []string{"org_state"}
)

func Test_DCRDefaultDataPrepares(t *testing.T) {
	type want struct {
		sqlExpectations sqlExpectation
		err             checkErr
	}
	tests := []struct {
		name    string
		prepare interface{}
		want    want
		object  interface{}
	}{
		{
			name:    "prepareDCRDefaultProjectQuery row absent",
			prepare: prepareDCRDefaultProjectQuery,
			want: want{
				sqlExpectations: mockQueriesScanErr(
					regexp.QuoteMeta(prepareDCRDefaultProjectStmt),
					nil,
					nil,
				),
			},
			object: DCRDefaultProjectInfo{Exists: false},
		},
		{
			name:    "prepareDCRDefaultProjectQuery present and active",
			prepare: prepareDCRDefaultProjectQuery,
			want: want{
				sqlExpectations: mockQuery(
					regexp.QuoteMeta(prepareDCRDefaultProjectStmt),
					prepareDCRDefaultProjectCols,
					[]driver.Value{
						domain.ProjectStateActive,
						"ro-1",
					},
				),
			},
			object: DCRDefaultProjectInfo{
				Exists:        true,
				Active:        true,
				ResourceOwner: "ro-1",
				State:         domain.ProjectStateActive,
			},
		},
		{
			name:    "prepareDCRDefaultProjectQuery present but deactivated",
			prepare: prepareDCRDefaultProjectQuery,
			want: want{
				sqlExpectations: mockQuery(
					regexp.QuoteMeta(prepareDCRDefaultProjectStmt),
					prepareDCRDefaultProjectCols,
					[]driver.Value{
						domain.ProjectStateInactive,
						"ro-2",
					},
				),
			},
			object: DCRDefaultProjectInfo{
				Exists:        true,
				Active:        false,
				ResourceOwner: "ro-2",
				State:         domain.ProjectStateInactive,
			},
		},
		{
			name:    "prepareDCRDefaultProjectQuery sql err",
			prepare: prepareDCRDefaultProjectQuery,
			want: want{
				sqlExpectations: mockQueryErr(
					regexp.QuoteMeta(prepareDCRDefaultProjectStmt),
					sql.ErrConnDone,
				),
				err: func(err error) (error, bool) {
					if !errors.Is(err, sql.ErrConnDone) {
						return fmt.Errorf("err should be sql.ErrConnDone got: %w", err), false
					}
					return nil, true
				},
			},
			object: DCRDefaultProjectInfo{},
		},
		{
			name:    "prepareDCRDefaultOrgQuery row absent",
			prepare: prepareDCRDefaultOrgQuery,
			want: want{
				sqlExpectations: mockQueriesScanErr(
					regexp.QuoteMeta(prepareDCRDefaultOrgStmt),
					nil,
					nil,
				),
			},
			object: DCRDefaultOrgInfo{Exists: false},
		},
		{
			name:    "prepareDCRDefaultOrgQuery present and active",
			prepare: prepareDCRDefaultOrgQuery,
			want: want{
				sqlExpectations: mockQuery(
					regexp.QuoteMeta(prepareDCRDefaultOrgStmt),
					prepareDCRDefaultOrgCols,
					[]driver.Value{
						domain.OrgStateActive,
					},
				),
			},
			object: DCRDefaultOrgInfo{
				Exists: true,
				Active: true,
				State:  domain.OrgStateActive,
			},
		},
		{
			name:    "prepareDCRDefaultOrgQuery present but deactivated",
			prepare: prepareDCRDefaultOrgQuery,
			want: want{
				sqlExpectations: mockQuery(
					regexp.QuoteMeta(prepareDCRDefaultOrgStmt),
					prepareDCRDefaultOrgCols,
					[]driver.Value{
						domain.OrgStateInactive,
					},
				),
			},
			object: DCRDefaultOrgInfo{
				Exists: true,
				Active: false,
				State:  domain.OrgStateInactive,
			},
		},
		{
			name:    "prepareDCRDefaultOrgQuery sql err",
			prepare: prepareDCRDefaultOrgQuery,
			want: want{
				sqlExpectations: mockQueryErr(
					regexp.QuoteMeta(prepareDCRDefaultOrgStmt),
					sql.ErrConnDone,
				),
				err: func(err error) (error, bool) {
					if !errors.Is(err, sql.ErrConnDone) {
						return fmt.Errorf("err should be sql.ErrConnDone got: %w", err), false
					}
					return nil, true
				},
			},
			object: DCRDefaultOrgInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertPrepare(t, tt.prepare, tt.object, tt.want.sqlExpectations, tt.want.err)
		})
	}
}
