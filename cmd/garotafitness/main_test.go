package main

import (
	"testing"

	"github.com/lewtec/lewkit/x/cmd"
	"github.com/stretchr/testify/require"
)

func TestParseExtract(t *testing.T) {
	t.Parallel()
	_, err := cmd.Parse[cmd.App[root]]()
	require.NoError(t, err)

	app, err := cmd.Parse[cmd.App[root]]("extract")
	require.NoError(t, err)
	require.NotNil(t, app.Args.Extract)
	require.Error(t, app.Args.Extract.Run(t.Context()))

	src := t.TempDir()
	dst := t.TempDir()
	app, err = cmd.Parse[cmd.App[root]]("extract", src, dst)
	require.NoError(t, err)
	require.NotNil(t, app.Args.Extract)
	require.Equal(t, src, app.Args.Extract.Source.Value())
	require.Equal(t, dst, app.Args.Extract.Dest.Value())

	app, err = cmd.Parse[cmd.App[root]]("--cpu", "2", "extract", src, dst)
	require.NoError(t, err)
	require.Equal(t, 2, app.Args.CPU.Value())

	_, err = cmd.Parse[cmd.App[root]]("--pprof", ":6060", "extract", src, dst)
	require.NoError(t, err)
}
