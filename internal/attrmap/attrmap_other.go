//go:build !linux

package attrmap

import "errors"

// Map is unavailable off Linux.
type Map struct{}

// Open always fails off Linux.
func Open(string) (*Map, error) { return nil, errors.New("attrmap: linux only") }

// Lookup is never reached off Linux.
func (*Map) Lookup(string) (map[string]string, error) { return nil, errors.New("attrmap: linux only") }
