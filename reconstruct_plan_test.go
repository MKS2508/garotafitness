package garotafitness

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/lucasew/garotafitness/setupdata"
	"github.com/stretchr/testify/require"
)

func TestInstalledManifestRelativeDestination(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ directory, name string }{
		{".", "Assets/payload.dat"},
		{"Checks", `..\Assets\payload.dat`},
		{"Verify/Nested", `..\..\Assets\payload.dat`},
	} {
		t.Run(tc.directory, func(t *testing.T) {
			s := newStaging()
			s.files["Assets/payload.dat"] = []byte("abc")
			for _, mode := range []string{"*", " "} {
				manifest := "900150983cd24fb0d6963f7d28e17f72 " + mode + tc.name + "\r\n"
				require.NoError(t, s.verifyInstalled(t.Context(), manifest, tc.directory))
				s.files["Assets/payload.dat"] = []byte("corrupt")
				require.ErrorContains(t, s.verifyInstalled(t.Context(), manifest, tc.directory), "installed checksum")
				s.files["Assets/payload.dat"] = []byte("abc")
			}
		})
	}
}

func TestOptionalVolumesFollowSetupRecords(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"fg-language.bin", "fg-optional-extras.bin"} {
		for _, optional := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", name, optional), func(t *testing.T) {
				op := setupdata.Operation{Kind: "extract", Source: "{src}\\" + name, Dest: "{app}", Optional: optional}
				components, err := sourceComponents([]setupdata.Operation{op})
				require.NoError(t, err)
				source := fstest.MapFS{checksumName: {Data: []byte("900150983cd24fb0d6963f7d28e17f72 *..\\" + name + "\n")}}
				errors := []error{verifyChecksums(t.Context(), source, nil, components), testPlan().run(t.Context(), []setupdata.Operation{op})}
				for _, err := range errors {
					if optional {
						require.NoError(t, err)
					} else {
						require.ErrorContains(t, err, "missing")
					}
				}
				required := op
				required.Optional = false
				for _, ops := range [][]setupdata.Operation{{op, required}, {required, op}} {
					components, err = sourceComponents(ops)
					require.NoError(t, err)
					require.False(t, components[name], "a required use must override optional uses")
				}
			})
		}
	}
}

func TestRecipeCaseOnlyRename(t *testing.T) {
	t.Parallel()
	p := testPlan()
	p.app.files["Assets/FILE.dat"] = []byte("payload")
	require.NoError(t, p.recipe(t.Context(), `ren Assets\FILE.dat file.dat`, "app", 0))
	require.Equal(t, map[string][]byte{"Assets/file.dat": []byte("payload")}, p.app.files)
}

func TestWaitDecodedPrefersDecodeErrOverCanceled(t *testing.T) {
	t.Parallel()
	want := errors.New("extract volume fg-08.bin: create tmp: not writable")
	p := &reconstructionPlan{
		decoded:   map[string]*reconstruction{},
		seen:      map[string]bool{},
		decodeErr: want,
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(context.Canceled)
	_, err := p.waitDecoded(ctx, "fg-05.bin")
	require.ErrorIs(t, err, want)
}

func TestWaitDecodedReturnsCancelCause(t *testing.T) {
	t.Parallel()
	want := errors.New("checksum: fg-03.bin mismatch")
	p := &reconstructionPlan{
		decoded: map[string]*reconstruction{},
		seen:    map[string]bool{},
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(want)
	_, err := p.waitDecoded(ctx, "fg-05.bin")
	require.ErrorIs(t, err, want)
}
