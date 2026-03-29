package middleware

import (
	"time"
)

// activeWindow is the look-back duration used to decide whether a user is
// "active".  It intentionally mirrors TokenRenewThreshold so that any
// successful auth call (including a token refresh) keeps the user counted.
const activeWindow = 8 * time.Hour

// trackerBufSize is the capacity of the inbound event channel.  A burst of up
// to this many record() calls can be enqueued without blocking.  If the buffer
// is full the event is silently dropped – the stats may be slightly
// under-counted but the main request path is never delayed.
const trackerBufSize = 2048

// activeTracker counts distinct users that have been active within activeWindow.
//
// Concurrency design
//
//   - Hot path (record): a single non-blocking channel send.  No mutex, no
//     allocation, effectively a single atomic CAS inside the runtime's channel
//     implementation.  If the buffer is full the update is dropped silently.
//   - Cold path (count / StatsHandler): sends a one-shot reply channel into
//     queryCh and waits.  All map access happens exclusively inside the single
//     run() goroutine, so no synchronisation primitives are needed there.
//   - GC: a time.Ticker inside run() prunes stale entries every minute so
//     memory stays proportional to the number of distinct active users, not
//     total historical users.
type activeTracker struct {
	// eventCh carries UINs from request handlers to the run goroutine.
	eventCh chan uint64
	// queryCh carries one-shot reply channels from StatsHandler to run.
	queryCh chan chan<- activeSnapshot
	// stopCh is closed to signal the run goroutine to exit.
	stopCh chan struct{}
}

// activeSnapshot is the response type for a count query.
type activeSnapshot struct {
	Count int
	AsOf  time.Time
}

func newActiveTracker() *activeTracker {
	t := &activeTracker{
		eventCh: make(chan uint64, trackerBufSize),
		queryCh: make(chan chan<- activeSnapshot),
		stopCh:  make(chan struct{}),
	}
	go t.run()
	return t
}

// record enqueues a UIN activity event. It never blocks.
func (t *activeTracker) record(uin uint64) {
	select {
	case t.eventCh <- uin:
	default:
		// buffer full – drop. stats may be slightly under-counted,
		// but the auth path is never stalled.
	}
}

// snapshot returns an activeSnapshot with the current count of distinct
// users seen within activeWindow. It blocks until the run goroutine responds.
func (t *activeTracker) snapshot() activeSnapshot {
	reply := make(chan activeSnapshot, 1)
	// Convert to send-only so run() can only write into it.
	t.queryCh <- (chan<- activeSnapshot)(reply)
	return <-reply
}

// stop shuts down the background goroutine. Safe to call more than once.
func (t *activeTracker) stop() {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
}

// run is the single goroutine that owns the seen map.
// All reads and writes to seen happen here, eliminating data races without
// any explicit locking.
func (t *activeTracker) run() {
	seen := make(map[uint64]time.Time)

	gc := time.NewTicker(time.Minute)
	defer gc.Stop()

	for {
		select {
		case <-t.stopCh:
			return

		case uin := <-t.eventCh:
			seen[uin] = time.Now()

		case reply := <-t.queryCh:
			now := time.Now()
			count := 0
			for _, last := range seen {
				if now.Sub(last) < activeWindow {
					count++
				}
			}
			reply <- activeSnapshot{Count: count, AsOf: now}

		case <-gc.C:
			// Prune expired entries so the map does not grow without bound.
			now := time.Now()
			for uin, last := range seen {
				if now.Sub(last) >= activeWindow {
					delete(seen, uin)
				}
			}
		}
	}
}
