package i3d

// Apply copies a Giants shapes container and decrypts each payload, matching
// the two-argument ConsoleApp1 shipped as Farming Simulator's fgpack.exe.
func Apply(in []byte) ([]byte, error) {
	return apply(in)
}
