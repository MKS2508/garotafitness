package mpzz

import (
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/test"
	"github.com/stretchr/testify/require"
)

func testdataRoot(t *testing.T) *lewpath.Root {
	t.Helper()
	r, err := lewpath.Open("testdata")
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	return r
}
