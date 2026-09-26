// Package fixtest opens a package-local testdata directory for tests.
package fixtest

import (
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/test"
	"github.com/stretchr/testify/require"
)

// Root opens ./testdata from the test process working directory.
func Root(t testing.TB) *lewpath.Root {
	t.Helper()
	r, err := lewpath.Open("testdata")
	require.NoError(t, err)
	test.CloseOnCleanup(t, r)
	return r
}
