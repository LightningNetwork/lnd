// +build !windows

package headerfs

import "fmt"

// singleTruncate truncates a single header from the end of the header file.
// This can be used in the case of a re-org to remove the last header from the
// end of the main chain.
//
// TODO(roasbeef): define this and the two methods above on a headerFile
// struct?
func (h *headerStore) singleTruncate() error {
	// In order to truncate the file, we'll need to grab the absolute size
	// of the file as it stands currently.
	fileInfo, err := h.file.Stat()
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()

	// Next, we'll determine the number of bytes we need to truncate from
	// the end of the file.
	var truncateLength int64
	switch h.indexType {
	case Block:
		truncateLength = 80
	case RegularFilter:
		truncateLength = 32
	default:
		return fmt.Errorf("unknown index type: %v", h.indexType)
	}

	// Finally, we'll use both of these values to calculate the new size of
	// the file and truncate it accordingly.
	newSize := fileSize - truncateLength
	return h.file.Truncate(newSize)
}
