package pool

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNilPool_SearchAndParallelize(t *testing.T) {
	// a nil pool runs everything on the current thread
	var p *Pool

	results := p.Search(3, func() any { return 7 })
	require.Len(t, results, 3)
	for _, r := range results {
		assert.Equal(t, 7, r)
	}

	// searchAlone retries until non-nil
	attempts := 0
	results = p.Search(2, func() any {
		attempts++
		if attempts < 5 {
			return nil
		}
		return 42
	})
	assert.Equal(t, 42, results[0])
	assert.Equal(t, 42, results[1])

	results = p.Parallelize(4, func(i int) any { return i * 2 })
	require.Len(t, results, 4)
	for i, r := range results {
		assert.Equal(t, i*2, r)
	}
}

func TestPool_SearchWithNilResults(t *testing.T) {
	p := NewPool(2)
	defer p.TearDown()

	// f runs concurrently on all workers, so the counter must be atomic
	var attempts atomic.Int64
	results := p.Search(3, func() any {
		n := attempts.Add(1)
		if n%2 == 0 {
			return nil
		}
		return int(n)
	})
	require.Len(t, results, 3)
	for _, r := range results {
		assert.NotNil(t, r)
	}
}

func TestPool_ParallelizeSingleWorker(t *testing.T) {
	p := NewPool(1)
	defer p.TearDown()

	results := p.Parallelize(8, func(i int) any { return i })
	require.Len(t, results, 8)
	for i, r := range results {
		assert.Equal(t, i, r)
	}
}

func TestPool_SearchMoreThanWorkers(t *testing.T) {
	p := NewPool(2)
	defer p.TearDown()

	// request more results than there are workers
	results := p.Search(10, func() any { return 1 })
	require.Len(t, results, 10)
	for _, r := range results {
		assert.Equal(t, 1, r)
	}
}

func TestPool_TearDownNil(t *testing.T) {
	var p *Pool
	p.TearDown() // must not panic
}

func TestLockedReader(t *testing.T) {
	data := []byte("hello world")
	lr := NewLockedReader(bytes.NewReader(data))

	out := make([]byte, 5)
	n, err := lr.Read(out)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", string(out))

	n, err = lr.Read(out)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, " world"[:5], string(out))

	// "hello world" has one byte left, then reading returns io.EOF
	n, err = lr.Read(out)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, byte('d'), out[0])

	_, err = lr.Read(out)
	assert.ErrorIs(t, err, io.EOF)
}

func TestLockedReader_Concurrent(t *testing.T) {
	// a shared reader read concurrently: all bytes must be read exactly once
	data := bytes.Repeat([]byte{0xAB}, 1000)
	lr := NewLockedReader(bytes.NewReader(data))

	var mu sync.Mutex
	total := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 10)
			for {
				n, err := lr.Read(buf)
				mu.Lock()
				total += n
				mu.Unlock()
				if err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1000, total)
}

// errReader always fails.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestLockedReader_Error(t *testing.T) {
	wantErr := errors.New("boom")
	lr := NewLockedReader(errReader{wantErr})
	_, err := lr.Read(make([]byte, 4))
	assert.ErrorIs(t, err, wantErr)
}
