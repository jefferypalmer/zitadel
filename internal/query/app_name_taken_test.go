package query

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"testing"
)

var (
	prepareAppNameExistsStmt = `SELECT 1 FROM projections.apps7 LIMIT 1`
	prepareAppNameExistsCols = []string{"?column?"}
)

func Test_AppNameExistsPrepares(t *testing.T) {
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
			name:    "name not taken",
			prepare: prepareAppNameExistsQuery,
			want: want{
				sqlExpectations: mockQueriesScanErr(
					regexp.QuoteMeta(prepareAppNameExistsStmt),
					nil,
					nil,
				),
			},
			object: false,
		},
		{
			name:    "name taken",
			prepare: prepareAppNameExistsQuery,
			want: want{
				sqlExpectations: mockQuery(
					regexp.QuoteMeta(prepareAppNameExistsStmt),
					prepareAppNameExistsCols,
					[]driver.Value{1},
				),
			},
			object: true,
		},
		{
			name:    "sql err",
			prepare: prepareAppNameExistsQuery,
			want: want{
				sqlExpectations: mockQueryErr(
					regexp.QuoteMeta(prepareAppNameExistsStmt),
					sql.ErrConnDone,
				),
				err: func(err error) (error, bool) {
					if !errors.Is(err, sql.ErrConnDone) {
						return fmt.Errorf("err should be sql.ErrConnDone got: %w", err), false
					}
					return nil, true
				},
			},
			object: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertPrepare(t, tt.prepare, tt.object, tt.want.sqlExpectations, tt.want.err)
		})
	}
}
