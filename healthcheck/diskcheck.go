// +build !windows,!solaris,!netbsd,!openbsd,!js

package healthcheck

import "syscall"

// AvailableDiskSpaceRatio returns ratio of available disk space to total
// capacity.
func AvailableDiskSpaceRatio(path string) (float64, error) {
	s := syscall.Statfs_t{}
	err := syscall.Statfs(path, &s)
	if err != nil {
		return 0, err
	}

	// Calculate our free blocks/total blocks to get our total ratio of
	// free blocks.
	return float64(s.Bfree) / float64(s.Blocks), nil
}

// AvailableDiskSpace returns the available disk space in bytes of the given
// file system.
func AvailableDiskSpace(path string) (uint64, error) {
	s := syscall.Statfs_t{}
	err := syscall.Statfs(path, &s)
	if err != nil {
		return 0, err
	}

	// Some OSes have s.Bavail defined as int64, others as uint64, so we
	// need the explicit type conversion here.
	return uint64(s.Bavail) * uint64(s.Bsize), nil // nolint:unconvert
}
