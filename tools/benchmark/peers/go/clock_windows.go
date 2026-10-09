package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

func init() {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	counter := kernel.NewProc("QueryPerformanceCounter")
	frequency := kernel.NewProc("QueryPerformanceFrequency")
	var hz int64
	ok, _, err := frequency.Call(uintptr(unsafe.Pointer(&hz)))
	if ok == 0 || hz <= 0 || hz > 1000000000 {
		panic(fmt.Sprintf("performance clock frequency: %v", err))
	}
	resolution := (1000000000 + hz - 1) / hz
	clockResolutionNS = &resolution
	clockName = "QueryPerformanceCounter"
	stamp = func() int64 {
		var ticks int64
		ok, _, err := counter.Call(uintptr(unsafe.Pointer(&ticks)))
		if ok == 0 || ticks < 0 {
			panic(fmt.Sprintf("performance clock: %v", err))
		}
		return (ticks/hz)*1000000000 + (ticks%hz)*1000000000/hz
	}
}
