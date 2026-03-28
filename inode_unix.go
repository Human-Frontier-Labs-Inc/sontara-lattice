//go:build !windows

package main

import (
	"os"
	"syscall"
)

func inodeFromInfo(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
