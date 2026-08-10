//go:build windows

package app

import "golang.org/x/sys/windows"

func diskUsage(path string) (uint64, uint64, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var available, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(pointer, &available, &total, &free); err != nil {
		return 0, 0, err
	}
	return total, available, nil
}
