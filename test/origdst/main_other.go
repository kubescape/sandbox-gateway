//go:build !linux

package main

import "log"

func main() { log.Fatal("origdst loads a BPF program and runs on Linux only") }
