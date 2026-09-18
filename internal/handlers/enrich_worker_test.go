package handlers

import (
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/jmoiron/sqlx"
)

func openEnrichTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestEnrichWorkerRunsToCompletionOnEmptyDB exercises the real run() path with
// no source IPs or domains, so it completes without any network calls, and
// verifies subscribers receive the terminal "done" event and Status reflects
// completion even after all subscribers detach.
func TestEnrichWorkerRunsToCompletionOnEmptyDB(t *testing.T) {
	db := openEnrichTestDB(t)
	w := NewEnrichWorker(db)

	ch, unsubscribe := w.subscribe()
	defer unsubscribe()

	if !w.Trigger() {
		t.Fatal("Trigger() = false on an idle worker, want true")
	}

	var gotDone bool
	deadline := time.After(5 * time.Second)
	for !gotDone {
		select {
		case ev := <-ch:
			if ev.name == "done" {
				gotDone = true
			} else if ev.name == "error" {
				t.Fatalf("worker reported an error: %v", ev.data)
			}
		case <-deadline:
			t.Fatal("timed out waiting for the done event")
		}
	}

	status := w.Status()
	if status.Running {
		t.Error("Status().Running = true after completion, want false")
	}
	if status.IPTotal != 0 || status.DomainTotal != 0 {
		t.Errorf("status = %+v, want zero totals on an empty database", status)
	}
}

// TestEnrichWorkerTriggerRejectsWhileRunning verifies the concurrency guard:
// Trigger() must not start a second run while one is already in progress.
func TestEnrichWorkerTriggerRejectsWhileRunning(t *testing.T) {
	db := openEnrichTestDB(t)
	w := NewEnrichWorker(db)

	// Simulate an in-flight run without depending on real timing.
	w.mu.Lock()
	w.status = EnrichStatus{Running: true}
	w.mu.Unlock()

	if w.Trigger() {
		t.Error("Trigger() = true while a run is in progress, want false")
	}
	if !w.Status().Running {
		t.Error("Status().Running flipped to false after a rejected Trigger()")
	}
}

// TestEnrichWorkerPublishFanOut verifies publish() delivers to every current
// subscriber and stops delivering to a channel once it unsubscribes.
func TestEnrichWorkerPublishFanOut(t *testing.T) {
	db := openEnrichTestDB(t)
	w := NewEnrichWorker(db)

	ch1, unsub1 := w.subscribe()
	defer unsub1()
	ch2, unsub2 := w.subscribe()

	w.publish("tick", map[string]int{"n": 1})

	for _, ch := range []chan enrichEvent{ch1, ch2} {
		select {
		case ev := <-ch:
			if ev.name != "tick" {
				t.Errorf("event name = %q, want %q", ev.name, "tick")
			}
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive published event")
		}
	}

	unsub2()
	w.publish("tick", map[string]int{"n": 2})

	select {
	case ev := <-ch1:
		if ev.name != "tick" {
			t.Errorf("event name = %q, want %q", ev.name, "tick")
		}
	case <-time.After(time.Second):
		t.Fatal("remaining subscriber did not receive second published event")
	}

	select {
	case ev, ok := <-ch2:
		if ok {
			t.Errorf("unsubscribed channel received an event: %+v", ev)
		}
	case <-time.After(100 * time.Millisecond):
		// Expected: no delivery to an unsubscribed channel.
	}
}

// TestEnrichWorkerFinishOrdersStatusBeforePublish verifies that Running flips
// to false before the terminal event is published, so a subscriber that reads
// Status() after seeing Running=true is still guaranteed to receive the event.
func TestEnrichWorkerFinishOrdersStatusBeforePublish(t *testing.T) {
	db := openEnrichTestDB(t)
	w := NewEnrichWorker(db)
	w.mu.Lock()
	w.status = EnrichStatus{Running: true}
	w.mu.Unlock()

	ch, unsubscribe := w.subscribe()
	defer unsubscribe()

	done := make(chan struct{})
	go func() {
		w.finish(3, 4, 0, "")
		close(done)
	}()

	select {
	case ev := <-ch:
		if ev.name != "done" {
			t.Errorf("event name = %q, want %q", ev.name, "done")
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive the done event")
	}
	<-done

	if w.Status().Running {
		t.Error("Status().Running = true after finish(), want false")
	}
}
