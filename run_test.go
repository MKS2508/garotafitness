package garotafitness

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/lewtec/lewkit/x/taskgroup"
	"github.com/stretchr/testify/require"
)

func TestEachEmpty(t *testing.T) {
	t.Parallel()
	require.NoError(t, withSession(t.Context(), func(ctx context.Context) error {
		return taskgroup.Each[int]{Name: "test", Items: nil, Fn: func(context.Context, *taskgroup.Status, int) error {
			require.FailNow(t, "ran")
			return nil
		}}.Run(ctx)
	}))
}

func TestEachOne(t *testing.T) {
	t.Parallel()
	var n atomic.Int32
	err := withSession(t.Context(), func(ctx context.Context) error {
		return taskgroup.Each[int]{
			Name:  "test",
			Items: []int{7},
			Fn: func(_ context.Context, _ *taskgroup.Status, v int) error {
				n.Add(int32(v))
				return nil
			},
		}.Run(ctx)
	})
	require.NoError(t, err)
	require.Equal(t, int32(7), n.Load())
}

func TestEachMany(t *testing.T) {
	t.Parallel()
	var n atomic.Int32
	items := make([]int, 16)
	err := withSession(t.Context(), func(ctx context.Context) error {
		return taskgroup.Each[int]{
			Name:  "test",
			Items: items,
			Fn: func(context.Context, *taskgroup.Status, int) error {
				n.Add(1)
				return nil
			},
		}.Run(ctx)
	})
	require.NoError(t, err)
	require.Equal(t, int32(16), n.Load())
}

func TestEachFirstError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	err := withSession(t.Context(), func(ctx context.Context) error {
		return taskgroup.Each[int]{
			Name:  "test",
			Items: []int{1, 2, 3, 4},
			Fn: func(_ context.Context, _ *taskgroup.Status, v int) error {
				if v == 1 {
					return boom
				}
				return nil
			},
		}.Run(ctx)
	})
	require.ErrorIs(t, err, boom)
}

func TestEachCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := withSession(ctx, func(ctx context.Context) error {
		return taskgroup.Each[int]{
			Name:  "test",
			Items: []int{1},
			Fn: func(context.Context, *taskgroup.Status, int) error {
				return errors.New("should not run")
			},
		}.Run(ctx)
	})
	require.ErrorIs(t, err, context.Canceled)
}
