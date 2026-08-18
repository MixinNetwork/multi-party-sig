package pool

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestSearchNoWorkerLeak runs many searches against a small pool. A worker that
// blocks forever on its completion signal (i.e. a leak) quickly exhausts the
// pool and makes this test hang; with correct synchronization every call
// returns promptly.
func TestSearchNoWorkerLeak(t *testing.T) {
	p := NewPool(2)
	defer p.TearDown()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			results := p.Search(3, func() any { return 1 })
			for _, r := range results {
				if r == nil {
					t.Error("Search returned a nil result")
					return
				}
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Search deadlocked: a worker was leaked and the pool exhausted")
	}
}

// TestParallelizeNoWorkerLeak does the same for Parallelize.
func TestParallelizeNoWorkerLeak(t *testing.T) {
	p := NewPool(2)
	defer p.TearDown()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			results := p.Parallelize(8, func(i int) any { return i })
			for j, r := range results {
				if r.(int) != j {
					t.Errorf("Parallelize returned wrong result at %d", j)
					return
				}
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Parallelize deadlocked: a worker was leaked and the pool exhausted")
	}
}

// TestParallelizeResultVisibility checks, under -race, that every result
// written by a worker is visible to the caller (store-before-signal).
func TestParallelizeResultVisibility(t *testing.T) {
	p := NewPool(4)
	defer p.TearDown()
	var sink atomic.Int64
	for round := 0; round < 100; round++ {
		results := p.Parallelize(16, func(i int) any { return i * i })
		for i, r := range results {
			if r.(int) != i*i {
				t.Fatalf("result %d not visible or wrong", i)
			}
			sink.Add(int64(r.(int)))
		}
	}
}

// TestSearchSingleWorker is the minimal reproduction of the historical
// deadlock: with one worker, the second Search call used to hang.
func TestSearchSingleWorker(t *testing.T) {
	p := NewPool(1)
	defer p.TearDown()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			p.Search(1, func() any { return 1 })
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Search with a single worker deadlocked")
	}
}
