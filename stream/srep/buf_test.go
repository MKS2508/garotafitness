package srep

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassIndex(t *testing.T) {
	t.Parallel()
	require.Equal(t, 0, classIndex(1))
	require.Equal(t, 0, classIndex(64))
	require.Equal(t, 1, classIndex(65))
	require.Equal(t, 1, classIndex(128))
	require.Equal(t, numClass-1, classIndex(maxBlock))
}

func TestGetPutSameClass(t *testing.T) {
	t.Parallel()
	a := getBuf(100)
	require.Equal(t, 128, cap(a))
	putBuf(a)
	b := getBuf(100)
	require.Equal(t, 128, cap(b))
	putBuf(b)
}
