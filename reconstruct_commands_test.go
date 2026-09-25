package garotafitness

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/lucasew/garotafitness/setupdata"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz/lzma"
)

func testPlan() *reconstructionPlan {
	return &reconstructionPlan{app: newStaging(), temp: newStaging(), volumes: map[string]Volume{}, remaining: map[string]int{}, decoded: map[string]*reconstruction{}, seen: map[string]bool{}}
}

func TestRecipeDrivenReconstruction(t *testing.T) {
	// These names, counts, locations, and compression options differ from the
	// corpus. The recipes supply every relationship between files.
	for _, count := range []int{1, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			p := testPlan()
			var recipe, moves strings.Builder
			for i := range count {
				name := fmt.Sprintf("chunk-%d", i)
				p.app.files["scratch/"+name+".raw"] = []byte("before")
				diff := binary.LittleEndian.AppendUint64(nil, 5)
				diff = binary.LittleEndian.AppendUint64(diff, 0)
				diff = append(diff, 5)
				diff = append(diff, "after"...)
				p.app.files["scratch/"+name+".patch"] = diff
				fmt.Fprintf(&recipe, "\"{tmp}\\engine\\x2.exe\" %s.raw %s.patch&&del %s.patch\n", name, name, name)
				fmt.Fprintf(&recipe, "cmd /c \"\"{tmp}\\engine\\fgpack.exe\" e -d16 -fb32 -lc2 -lp1 -pb1 %s.raw %s.packed&&del %s.raw\"\n", name, name, name)
				fmt.Fprintf(&moves, "move \"scratch\\%s.packed\" \"Assets\\chapter-%d.dat\"\n", name, i)
			}
			moves.WriteString("rd /q /s scratch\ndel \"installer note.txt\"\n")
			p.temp.files["engine/jobs.txt"] = []byte(recipe.String())
			p.temp.files["engine/build.bat"] = []byte("\"{tmp}\\engine\\run.exe\" \" \" https://example.invalid \"{tmp}\\engine\\jobs.txt\" 0\ndel \"{tmp}\\engine\\jobs.txt\"\n")
			p.temp.files["relocate.bat"] = []byte(moves.String())
			p.app.files["installer note.txt"] = []byte("temporary")
			ops := []setupdata.Operation{
				{Kind: "command", Program: "{tmp}\\engine\\build.bat", WorkDir: "{app}\\scratch"},
				{Kind: "command", Program: "{cmd}", Args: "/C call \"{tmp}\\relocate.bat\"", WorkDir: "{app}"},
			}
			require.NoError(t, p.run(t.Context(), ops))
			require.Len(t, p.app.files, count)
			for i := range count {
				b := p.app.files[fmt.Sprintf("Assets/chapter-%d.dat", i)]
				require.GreaterOrEqual(t, len(b), 13)
				require.Equal(t, byte((1*5+1)*9+2), b[0], "LZMA properties from recipe")
				require.Equal(t, uint32(1<<16), binary.LittleEndian.Uint32(b[1:]), "LZMA dictionary from recipe")
				r, err := lzma.NewReader(bytes.NewReader(b))
				require.NoError(t, err)
				got, err := io.ReadAll(r)
				require.NoError(t, err)
				require.Equal(t, "after", string(got))
			}
		})
	}
}

func TestRecipeReplacementsAndManifestAppend(t *testing.T) {
	p := testPlan()
	p.temp.files["tasks/list.txt"] = []byte("ROOT\\payload")
	require.NoError(t, p.command(t.Context(), "{tmp}\\fart.exe", "-w *.txt ROOT \"{app}\"", "tmp/tasks", 0))
	require.Equal(t, "{app}\\payload", string(p.temp.files["tasks/list.txt"]))
	p.app.files["Verify/base.md5"] = []byte("first\n")
	p.app.files["Verify/extra.addon"] = []byte("second\n")
	require.NoError(t, p.command(t.Context(), "{cmd}", "/C \"copy /b base.md5+*.addon&&del *.addon\"", "app/Verify", 0))
	require.Equal(t, "first\nsecond\n", string(p.app.files["Verify/base.md5"]))
	require.NotContains(t, p.app.files, "Verify/extra.addon")
}

func TestRecipeFGPackTwoArgAndSevenZ(t *testing.T) {
	p := testPlan()
	p.app.files["inner/0001.fgu"] = []byte("one")
	p.app.files["inner/0002.fgu"] = []byte("two")
	p.app.files["0001.shapes"] = []byte("shape")
	require.NoError(t, p.recipe(t.Context(), `fgpack.exe 0001.shapes 0001.fgr_`, "app", 0))
	require.Greater(t, len(p.app.files["0001.fgr_"]), 0)
	require.NoError(t, p.recipe(t.Context(), `7z.exe a -ms=off -mtc=off -mtm=off -mta=off -m0=lzma:x=4:d=512k inner.fgpack inner\*.fgu`, "app", 0))
	require.Greater(t, len(p.app.files["inner.fgpack"]), 32)
	require.Equal(t, []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, p.app.files["inner.fgpack"][:6])
}

func TestX4UnknownHash(t *testing.T) {
	p := testPlan()
	p.temp.files["x4.exe"] = []byte("not-giants")
	p.app.files["dlc/1.xml"] = []byte("hi")
	err := p.recipe(t.Context(), `"{tmp}\x4.exe" dlc out.dlc 02 01`, "app", 0)
	if !errors.Is(err, errUnknownToolHash) {
		t.Fatalf("err %v", err)
	}
}

func TestRecipeRejectsUnknownProgramsAndEscapes(t *testing.T) {
	for _, line := range []string{"unknown.exe input output", "del ../../escape", "del {src}\\fg-01.bin", "echo harmless | unknown.exe", "move missing destination"} {
		p := testPlan()
		require.Error(t, p.recipe(t.Context(), line, "app", 0), "accepted %q", line)
	}
	for _, name := range []string{"{app}\\..\\src\\source.bin", "{tmp}\\..\\app\\file", "/etc/passwd", "C:\\escape"} {
		_, err := virtualPath(name, "")
		require.Error(t, err, "accepted %q", name)
	}
}
