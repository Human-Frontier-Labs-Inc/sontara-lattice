//go:build windows

package main

import "os"

func inodeFromInfo(info os.FileInfo) uint64 {
	return 0
}
