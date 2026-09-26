package storing

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewReader(t *testing.T) {
	t.Parallel()
	r, err := NewReader(strings.NewReader("raw"))
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "raw", string(got))
	_, err = NewReader(nil)
	require.Error(t, err)
}
