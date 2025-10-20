package org.logstash.plugins.inputs.http.util;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.PrimitiveIterator;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.IntStream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

class ExecutionObserverTest {
    @Test
    void testBasicFunctionality() {
        final LongAdder nanos = new LongAdder();
        final ExecutionObserver observer = new ExecutionObserver(nanos::longValue);

        assertThat(observer.anyExecuting(), is(false));
        assertThat(observer.anyExecuting(Duration.ofSeconds(1)), is(false));

        nanos.add(Duration.ofSeconds(10).toNanos());
        assertThat(observer.anyExecuting(), is(false));
        assertThat(observer.anyExecuting(Duration.ofSeconds(1)), is(false));

        final ExecutionObserver.Execution exe1 = observer.startExecution();
        assertThat(observer.anyExecuting(), is(true));
        assertThat(observer.anyExecuting(Duration.ofNanos(1)), is(false));
        assertThat(observer.anyExecuting(Duration.ofSeconds(1)), is(false));

        nanos.add(Duration.ofSeconds(10).toNanos());
        assertThat(observer.anyExecuting(), is(true));
        assertThat(observer.anyExecuting(Duration.ofNanos(1)), is(true));
        assertThat(observer.anyExecuting(Duration.ofSeconds(1)), is(true));
        assertThat(observer.anyExecuting(Duration.ofSeconds(10).minus(Duration.ofNanos(1))), is(true));
        assertThat(observer.anyExecuting(Duration.ofSeconds(10)), is(true));
        assertThat(observer.anyExecuting(Duration.ofSeconds(10).plus(Duration.ofNanos(1))), is(false));

        exe1.markComplete();
        assertThat(observer.anyExecuting(), is(false));
        assertThat(observer.anyExecuting(Duration.ofSeconds(1)), is(false));
    }

    @Test
    void testManyConcurrentExecutions() {
        final LongAdder nanos = new LongAdder();
        final ExecutionObserver observer = new ExecutionObserver(nanos::longValue);
        final PrimitiveIterator.OfLong randomLong = ThreadLocalRandom.current().longs(1L, 1_000_000_000L).iterator();

        // mark the beginning of several executions, advancing the nano clock in randomized increments
        nanos.add(randomLong.next());
        final Handle exe1 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());
        final Handle exe2 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());
        final Handle exe3 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next()); // because we're recording two for the same nanotime
        final Handle exe4a = new Handle(nanos.longValue(), observer.startExecution());
        final Handle exe4b = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());
        final Handle exe5 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());
        final Handle exe6 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());
        final Handle exe7 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());
        final Handle exe8 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());
        final Handle exe9 = new Handle(nanos.longValue(), observer.startExecution());

        // all are still running, so exe1 is the longest-running
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe1.nanoTime)));

        // mark several intermediates complete, and ensure exe1 is still the longest-running
        exe2.execution.markComplete();
        exe3.execution.markComplete();
        exe7.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe1.nanoTime)));

        // mark exe1 complete, and ensure that exe4(a/b) are the longest-running
        exe1.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe4a.nanoTime)));
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe4b.nanoTime)));

        // mark exe4a complete, but exe4b is still the oldest
        exe4a.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe4a.nanoTime)));

        // mark exe5 complete, but exe4b is still the oldest
        exe5.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe4a.nanoTime)));

        // mark exe4b complete, so now exe6 is the oldest
        exe4b.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe6.nanoTime)));

        // mark exe9 complete, but exe6 is still the oldest
        exe9.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe6.nanoTime)));

        // advance the clock again, adding another
        nanos.add(1000000000L);
        final Handle exe10 = new Handle(nanos.longValue(), observer.startExecution());

        nanos.add(10000000000L);

        // mark exe10 complete, but exe6 is still the oldest
        exe10.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe6.nanoTime)));

        // mark exe6 complete, now exe8 is the oldest
        exe6.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe8.nanoTime)));

        // mark exe8 complete, now there are none waiting
        exe8.execution.markComplete();
        assertThat(observer.anyExecuting(), is(false));

        // start two more
        final Handle exe11 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());
        final Handle exe12 = new Handle(nanos.longValue(), observer.startExecution());
        nanos.add(randomLong.next());

        // exe11 is our oldest
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe11.nanoTime)));

        // mark exe11 complete; exe12 is now our oldest
        exe11.execution.markComplete();
        validateLongestExecuting(observer, Duration.ofNanos(nanos.longValue()).minus(Duration.ofNanos(exe12.nanoTime)));

        // mark exe12 complete; none executing
        exe12.execution.markComplete();
        assertThat(observer.anyExecuting(), is(false));

        ExecutionObserver.Stats stats = observer.stats();
        assertThat(stats.nodes, is(both(greaterThan(0)).and(lessThanOrEqualTo(3))));
        assertThat(stats.executing, is(0));
    }

    private void validateLongestExecuting(final ExecutionObserver observer, final Duration expectedLongestExecutionDuration) {
        assertThat(observer.anyExecuting(), is(true));
        assertThat(observer.longestExecuting(), equalTo(Optional.of(expectedLongestExecutionDuration)));
        assertThat(observer.anyExecuting(expectedLongestExecutionDuration), is(true));
        assertThat(observer.anyExecuting(expectedLongestExecutionDuration.plus(Duration.ofNanos(1))), is(false));
    }


    @RepeatedTest(value = 10)
    void testThreadSafetyBruteForce() {
        final int scale = 1000;
        final int concurrency = 100;
        final ExecutorService executorService = Executors.newFixedThreadPool(concurrency);
        final ExecutionObserver observer = new ExecutionObserver();

        final AtomicInteger maxConcurrency = new AtomicInteger(0);
        final AtomicInteger maxNodes = new AtomicInteger(0);

        try {
            // submit $scale tasks to the executor, each of which sleeps a variable amount
            // before triggering an observed execution that lasts a random length. The goal
            // is to have many concurrent and interleaved executions.
            CompletableFuture<Void> allRun = CompletableFuture.allOf(IntStream.range(0, scale)
                    .mapToObj((idx) ->
                            CompletableFuture.runAsync(() -> {
                                interruptibleSleep(ThreadLocalRandom.current().nextInt(5));
                                observer.observeExecution(() -> {
                                    final ExecutionObserver.Stats stats = observer.stats();
                                    maxConcurrency.accumulateAndGet(stats.executing, Math::max);
                                    maxNodes.accumulateAndGet(stats.nodes, Math::max);
                                    interruptibleSleep(ThreadLocalRandom.current().nextInt(1, 100));
                                });
                            }, executorService))
                    .toArray(CompletableFuture[]::new));

            // wait until all have run
            allRun.get(30, TimeUnit.SECONDS);

            // at some point in the execution, we want there to be many things running concurrently,
            // but we also want the max uncompacted nodes to never get too high
            assertThat(maxConcurrency.get(), is(greaterThan(1)));
            assertThat(maxNodes.get(), is(lessThanOrEqualTo(concurrency * 2)));

            // without queries, we should at least have some compaction
            final ExecutionObserver.Stats preCompactionStats = observer.stats();
            assertThat(preCompactionStats.executing, is(0));
            assertThat(preCompactionStats.nodes, is(both(greaterThan(0)).and(lessThan(concurrency))));

            // query triggers tail compaction, leaving 2 or fewer nodes.
            assertThat(observer.anyExecuting(), is(false));
            final ExecutionObserver.Stats postCompactionStats = observer.stats();
            assertThat(postCompactionStats.executing, is(0));
            assertThat(postCompactionStats.nodes, is(both(greaterThan(0)).and(lessThanOrEqualTo(2))));


        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        } finally {
            executorService.shutdown();
        }
    }

    static class Handle {
        final long nanoTime;
        final ExecutionObserver.Execution execution;

        public Handle(long nanoTime, ExecutionObserver.Execution execution) {
            this.nanoTime = nanoTime;
            this.execution = execution;
        }
    }

    static void interruptibleSleep(final int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}