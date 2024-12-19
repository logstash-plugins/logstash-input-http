package org.logstash.plugins.inputs.http.util;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/**
 * An {@code ExecutionObserver} observes possibly-concurrent execution, and provides information about the
 * longest-running observed execution.
 *
 * <p>
 *     It is concurrency-safe and non-blocking, and uses plain memory access where practical.
 * </p>
 */
public class ExecutionObserver {
    private final AtomicReference<Execution> tail; // newest execution
    private final AtomicReference<Execution> head; // oldest execution

    private final LongSupplier nanosSupplier;

    public ExecutionObserver() {
        this(System::nanoTime);
    }

    ExecutionObserver(final LongSupplier nanosSupplier) {
        this.nanosSupplier = nanosSupplier;
        final Execution anchor = new Execution(nanosSupplier.getAsLong(), true);
        this.tail = new AtomicReference<>(anchor);
        this.head = new AtomicReference<>(anchor);
    }

    /**
     * @see ExecutionObserver#anyExecuting(Duration)
     * @return true if there are any active executions.
     */
    public boolean anyExecuting() {
        return this.anyExecuting(Duration.ZERO);
    }

    /**
     * @param minimumDuration a threshold to exclude young executions
     * @return true if any active execution has been running for at least the provided {@code Duration}
     */
    public boolean anyExecuting(final Duration minimumDuration) {
        final Execution headExecution = compactHead();
        if (headExecution.isComplete) {
            return false;
        } else {
            return nanosSupplier.getAsLong() - headExecution.startNanos >= minimumDuration.toNanos();
        }
    }

    // visible for test
    Optional<Duration> longestExecuting() {
        final Execution headExecution = compactHead();
        if (headExecution.isComplete) {
            return Optional.empty();
        } else {
            return Optional.of(Duration.ofNanos(nanosSupplier.getAsLong() - headExecution.startNanos));
        }
    }

    // test inspections
    Stats stats() {
        int nodes = 0;
        int executing = 0;

        Execution candidate = this.head.get();
        while (candidate != null) {
            nodes += 1;
            if (!candidate.isComplete) {
                executing += 1;
            }
            candidate = candidate.next.get();
        }
        return new Stats(nodes, executing);
    }

    static class Stats {
        final int nodes;
        final int executing;

        Stats(int nodes, int executing) {
            this.nodes = nodes;
            this.executing = executing;
        }
    }

    @FunctionalInterface
    public interface ExceptionalSupplier<T, E extends Throwable> {
        T get() throws E;
    }

    public <T,E extends Throwable> T observeExecution(final ExceptionalSupplier<T,E> supplier) throws E {
        final Execution execution = startExecution();
        try {
            return supplier.get();
        } finally {
            final boolean isCompact = execution.markComplete();
            if (!isCompact) {
                this.compactHead();
            }
        }
    }

    @FunctionalInterface
    public interface ExceptionalRunnable<E extends Throwable> {
        void run() throws E;
    }

    public <E extends Throwable> void observeExecution(final ExceptionalRunnable<E> runnable) throws E {
        observeExecution(() -> { runnable.run(); return null; });
    }

    // visible for test
    Execution startExecution() {
        final Execution newTail = new Execution(nanosSupplier.getAsLong());

        // atomically attach the new execution as a new (detached) tail
        final Execution oldTail = this.tail.getAndSet(newTail);
        // attach our new tail to the old one
        oldTail.linkNext(newTail);

        return newTail;
    }

    private Execution compactHead() {
        return this.head.updateAndGet(Execution::seekHead);
    }

    static class Execution {

        private final long startNanos;

        private volatile boolean isComplete;
        private final AtomicReference<Execution> next = new AtomicReference<>();

        Execution(long startNanos) {
            this(startNanos, false);
        }

        Execution(final long startNanos,
                  final boolean isComplete) {
            this.startNanos = startNanos;
            this.isComplete = isComplete;
        }

        /**
         * marks this execution as complete
         * @return true if the completion resulted in a compaction
         */
        boolean markComplete() {
            isComplete = true;

            final Execution preCompletionNext = this.next.get();
            if (preCompletionNext != null) {
                final Execution result = this.next.updateAndGet(Execution::seekHead);
                return result != preCompletionNext;
            }

            return false;
        }

        private void linkNext(final Execution proposedNext) {
            final Execution result = next.updateAndGet((ex) -> ex == null ? proposedNext : ex);
            if (result != proposedNext) {
                throw new IllegalStateException();
            }
        }

        /**
         * @return the first {@code Execution} that is either not yet complete
         *         or is the current tail, possibly itself.
         */
        private Execution seekHead() {
            Execution compactedHead = this;
            Execution candidate = this.next.get();
            while (candidate != null && compactedHead.isComplete) {
                compactedHead = candidate;
                candidate = candidate.next.get();
            }
            return compactedHead;
        }
    }
}
