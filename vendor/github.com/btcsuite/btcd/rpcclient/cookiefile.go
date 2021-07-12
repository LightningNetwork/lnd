// Copyright (c) 2017 The Namecoin developers
// Copyright (c) 2019 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcclient

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func readCookieFile(path string) (username, password string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan()
	err = scanner.Err()
	if err != nil {
		return
	}
	s := scanner.Text()

	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("malformed cookie file")
		return
	}

	username, password = parts[0], parts[1]
	return
}
