package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Singleflight tests remain in OSA — cache tests live in Open-Cache-Go.

func TestSingleflightRunsTheFetchOnce(t *testing.T) {
	sf := newSingleflight()
	var calls int64
	release := make(chan struct{})

	const n = 20
	var wg sync.WaitGroup
	results := make([][]byte, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := sf.do("same-key", func() ([]byte, error) {
				atomic.AddInt64(&calls, 1)
				<-release
				return []byte("payload"), nil
			})
			if err != nil {
				t.Errorf("do: %v", err)
			}
			results[i] = v
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("fetch ran %d times, want 1", got)
	}
	for i, v := range results {
		if string(v) != "payload" {
			t.Fatalf("waiter %d got %q", i, v)
		}
	}
}

func TestSingleflightSurvivesAPanickingFetch(t *testing.T) {
	sf := newSingleflight()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := sf.do("boom", func() ([]byte, error) { panic("upstream exploded") })
		if err == nil {
			t.Error("a panicking fetch must surface as an error")
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waiter deadlocked on a panicking fetch")
	}
	v, err := sf.do("boom", func() ([]byte, error) { return []byte("ok"), nil })
	if err != nil || string(v) != "ok" {
		t.Fatalf("key not released after the panic: v=%q err=%v", v, err)
	}
}

func TestSingleflightDoesNotJoinAFinishedFlight(t *testing.T) {
	sf := newSingleflight()
	var calls int64
	fn := func() ([]byte, error) {
		atomic.AddInt64(&calls, 1)
		return []byte("v"), nil
	}
	_, _ = sf.do("k", fn)
	_, _ = sf.do("k", fn)
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("sequential calls ran the fetch %d times, want 2", got)
	}
}

func TestSingleflightErrorPropagation(t *testing.T) {
	sf := newSingleflight()
	_, err := sf.do("err-key", func() ([]byte, error) {
		return nil, fmt.Errorf("upstream failed")
	})
	if err == nil {
		t.Fatal("expected error")
	}
}
