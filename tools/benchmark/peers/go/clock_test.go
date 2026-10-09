package main

import (
	"testing"
	"time"
)

func TestBenchmarkClock(t *testing.T) {
	previous := stamp()
	time.Sleep(time.Millisecond)
	if current := stamp(); current <= previous {
		t.Fatalf("monotonic clock did not advance: %d <= %d", current, previous)
	}
	if clockResolutionNS != nil && *clockResolutionNS <= 0 {
		t.Fatal("invalid clock resolution")
	}
}
