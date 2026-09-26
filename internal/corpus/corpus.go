package corpus

import (
	"io"
	"os"
	"testing"

	lewpath "github.com/lewtec/lewkit/x/path"
	"github.com/lewtec/lewkit/x/test"
	"github.com/stretchr/testify/require"
)

func Dir(t testing.TB) string {
	t.Helper()
	return DirEnv(t, "GAROTAFITNESS_CORPUS")
}

func DirEnv(t testing.TB, env string) string {
	t.Helper()
	dir := os.Getenv(env)
	if dir == "" {
		t.Skip("set " + env)
	}
	return dir
}

func Open(t testing.TB) *lewpath.Root {
	t.Helper()
	return OpenEnv(t, "GAROTAFITNESS_CORPUS")
}

func OpenEnv(t testing.TB, env string) *lewpath.Root {
	t.Helper()
	r, err := lewpath.Open(DirEnv(t, env))
	if err != nil {
		t.Skip("corpus not mounted")
	}
	test.CloseOnCleanup(t, r)
	return r
}

func File(t testing.TB, name string) io.ReadSeeker {
	t.Helper()
	return FileEnv(t, "GAROTAFITNESS_CORPUS", name)
}

func FileEnv(t testing.TB, env, name string) io.ReadSeeker {
	t.Helper()
	f, err := lewpath.New(name).Open(OpenEnv(t, env))
	if err != nil {
		t.Skip("corpus not mounted")
	}
	test.CloseOnCleanup(t, f)
	rs, ok := f.(io.ReadSeeker)
	require.Truef(t, ok, "%s: %T is not a ReadSeeker", name, f)
	return rs
}

func ReadFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := lewpath.New(name).ReadFile(Open(t))
	if err != nil {
		t.Skip("corpus not mounted")
	}
	return b
}
