package healthcheck

// AvailableDiskSpaceRatio returns ratio of available disk space to total
// capacity.
func AvailableDiskSpaceRatio(path string) (float64, error) {
	return 0, fmt.Errorf("disk space check not supported in WebAssembly")
}

// AvailableDiskSpace returns the available disk space in bytes of the given
// file system.
func AvailableDiskSpace(path string) (uint64, error) {
	return 0, fmt.Errorf("disk space check not supported in WebAssembly")
}
