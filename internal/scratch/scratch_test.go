package scratch

import (
	"strings"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/test"
	"github.com/stretchr/testify/require"
)

func TestMkdirTempUsesWithDir(t *testing.T) {
	t.Parallel()
	dest := t.TempDir()
	parent, err := lewpath.Open(dest)
	require.NoError(t, err)
	test.CloseOnCleanup(t, parent)
	ctx := WithDir(t.Context(), dest)
	d, err := MkdirTemp(ctx, "x5n-")
	require.NoError(t, err)
	rel := d.Rel().String()
	require.True(t, strings.HasPrefix(rel, "tmp/"))
	require.Contains(t, rel, "x5n-")
	ok, err := d.Rel().IsDir(parent)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, d.Close())
	ok, err = d.Rel().Exists(parent)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestMkdirTempRequiresWithDir(t *testing.T) {
	t.Parallel()
	_, err := MkdirTemp(t.Context(), "x5n-")
	require.Error(t, err)
}
