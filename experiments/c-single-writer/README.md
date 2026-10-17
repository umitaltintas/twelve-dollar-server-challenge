# Single writer, many readers: the multi-core design in C

This is an experiment, not a submission. It builds the design proposed at the end of
[`../asm-multicore`](../asm-multicore/README.md): several cores serve reads, and one thread
owns every write and commits them in batches. It is written in C rather than assembly because
the threads need per-thread state and a queue between them. The assembly server keeps its state
in globals, built around a single event loop.

The same rule-breaking setup as `asm-multicore` applies: more than one core, no fd limit, no
keep-alive budgets. Nothing here should be compared with challenge scores.

## Design

One process, with these threads:

- **Reader threads**, one per core by default (`THREADS` overrides). Each has:
  - its own `SO_REUSEPORT` listen socket, so the kernel spreads connections across readers;
  - its own edge-triggered epoll loop;
  - its own read-only SQLite connection.

  Readers parse requests, check JWTs, validate bodies and answer `GET /feed`, `GET /posts/:id`
  and `GET /health` on their own. In WAL mode, readers never wait for each other or for the writer.
- **One writer thread**, which owns the only connection that writes.
  1. Readers push `POST /posts` and likes onto a lock-free queue. They wake the writer with an
     eventfd, but only when the queue was empty.
  2. The writer takes everything queued while it was busy and runs it in one transaction
     (group commit).
  3. It hands each result back to the reader that owns the connection: one lock-free list and
     one eventfd wakeup per reader per batch.
  4. That reader builds and sends the response, so the writer makes no socket calls.
- **One checkpoint thread**, as in the assembly server.

While a connection has a write with the writer, it is paused: nothing more is read or parsed
from it until that response has been sent. Pipelined requests are therefore still answered in order.
Responses are sent only after the commit, as before.

Parsing, JSON, JWT checks and response bytes follow the assembly submission one for one:

- `test/test.sh` passes (42/42).
- In a 76-case byte-for-byte comparison with the assembly server, no response differed. The
  cases cover odd JSON, Unicode escapes, JWT edge cases, pipelining, `Connection: close`, and
  requests split across packets.

```bash
bash build.sh                       # downloads the pinned SQLite amalgamation, builds bin/server
SQLITE_PATH=feed.db PORT=80 HOST=0.0.0.0 bin/server
```

## Results

Setup:

- **Machine:** the 8-vCPU x86-64 KVM server from `asm-multicore` (AMD EPYC-Milan, Ubuntu 24.04,
  kernel 6.8). The server was pinned to 3 cores, with no fd limit.
- **Load:** the `asm-multicore` load generator on 4 other cores, about 24k connections per
  source address, over loopback in the server's network namespace.
- **Timing:** 90 s ramp, then a 2-minute hold.

The rows marked "same day" were run back to back with the same setup. The 256k assembly row
comes from `asm-multicore`.

| Server (3 cores) | Users | Errors | p95 | p99 | Server CPU |
|---|---|---|---|---|---|
| Assembly, 3 processes (`asm-multicore`) | 256,000 | 0 | 28–31 ms | 61–92 ms | 146% |
| **C, single writer** | 256,000 | 0 | **1.6–1.9 ms** | 6.5–41 ms | 202% |
| Assembly, 3 processes (same day) | 384,000 | 0 | 682–707 ms ✗ | 980–1,023 ms ✗ | 151% |
| **C, single writer** (same day) | 384,000 | 0 | **251–291 ms** ✓ | **406–415 ms** ✓ | 255% |
| C, single writer | 448,000 | 0 | 646–657 ms ✗ | 855–863 ms | 255% |
| C, single writer | 512,000 | 0 | 716–735 ms ✗ | 970–981 ms | 254% |

✓/✗ use the challenge's pass limits: p95 under 500 ms and p99 under 1 s.

What they show:

- **The write lock is gone as a limit.** At 384k, the assembly processes failed while each core
  was only half busy, because they kept waiting for the SQLite write lock. The single-writer
  server passed the same load on the same three cores. At 256k, its p95 was 15 times lower.
- **The new limit is CPU.** From 384k up, the server sits at about 255% of the 300% it has, and
  latency grows from queueing (p50 rises from 0.4 ms at 256k to about 28 ms at 384k and 425 ms
  at 448k). The limit with three cores is somewhere between 384k and 448k.
- **It uses more CPU per request than the assembly processes.** At 256k it used 202% where they used 146%.
  - It is not contention between readers. A closed-loop `GET /feed` test scales almost linearly:
    about 42k req/s on one core, 130k on three (native arm64, on a laptop).
  - Two likely causes:
    - Every read is its own SQLite read transaction. In the assembly server, most reads run
      inside the batch's write transaction.
    - The handoffs between threads add eventfd wakeups and context switches for every write.

  I didn't profile this on the x86 server.
