package com.github.lisama569.sbomriskservicejava.ingest;

import com.github.lisama569.sbomriskservicejava.model.IngestResult;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

/**
 * Result of running an action through the guard: the result plus whether it
 * was replayed from a previous identical submission.
 */
record GuardedResult(IngestResult result, boolean replayed) {
}

/**
 * Serializes concurrent submissions targeting the same document id and replays
 * the first completed result for all subsequent (including concurrent) calls.
 *
 * <p>Semantics:
 * <ul>
 *   <li>Different document ids execute concurrently without contention.</li>
 *   <li>The first call for a document id computes the result; any concurrent
 *       or later call with the same id blocks on the per-id lock and receives
 *       the cached result marked as a replay.</li>
 *   <li>Only successful computations are cached; a document-level failure is
 *       retried by the next caller.</li>
 * </ul>
 */
@Component
public class IdempotencyGuard {

    private record Slot(Object lock, Optional<IngestResult> cached) {
        Slot withCached(IngestResult result) {
            return new Slot(lock, Optional.of(result));
        }
    }

    private final ConcurrentMap<String, Slot> slots = new ConcurrentHashMap<>();

    public GuardedResult execute(String documentId, Supplier<IngestResult> action) {
        Slot slot = slots.computeIfAbsent(documentId, id -> new Slot(new Object(), Optional.empty()));
        synchronized (slot.lock()) {
            Slot current = slots.get(documentId);
            if (current.cached().isPresent()) {
                return new GuardedResult(current.cached().get(), true);
            }
            IngestResult result = action.get();
            slots.put(documentId, current.withCached(result));
            return new GuardedResult(result, false);
        }
    }

    /** Test/maintenance helper: forget a cached submission. */
    public void invalidate(String documentId) {
        slots.computeIfPresent(documentId, (id, slot) ->
                new Slot(slot.lock(), Optional.empty()));
    }
}
