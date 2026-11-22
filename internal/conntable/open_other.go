//go:build !linux

package conntable

import "errors"

// Open is only available on Linux, where the maps live.
func Open(string) (Table, error) {
	return nil, errors.New("conntable: pinned maps need Linux")
}
