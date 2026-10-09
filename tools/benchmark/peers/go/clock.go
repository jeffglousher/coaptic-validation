package main

import "time"

var clockOrigin = time.Now()
var stamp = func() int64 { return time.Since(clockOrigin).Nanoseconds() }
var clockName = "Go time monotonic"
var clockResolutionNS *int64
