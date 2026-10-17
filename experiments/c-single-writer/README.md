# Single writer, many readers: the multi-core design in C

This is an experiment, not a submission. It builds the design proposed at the end of
[`../asm-multicore`](../asm-multicore/README.md): several cores serve reads, and one writer owns
every write and commits them in batches. It is written in C rather than assembly because the
readers need per-reader state and a queue to the writer. The assembly server keeps its state in
globals, built around a single event loop.

The same rule-breaking setup as `asm-multicore` applies: more than one core, no fd limit, no
keep-alive budgets. Nothing here should be compared with challenge scores.

## Design

**Readers**, one per core by default (`THREADS` overrides). Each has:
- its own `SO_REUSEPORT` listen socket, so the kernel spreads connections across readers;
- its own edge-triggered epoll loop;
- its own read-only SQLite connection.

Readers parse requests, check JWTs, validate bodies and answer `GET /feed`, `GET /posts/:id`
and `GET /health` on their own. In WAL mode, readers never wait for each other or for the writer.

**One writer**, which owns the only connection that writes:
1. Readers hand it `POST /posts` and likes.
2. It takes everything that queued up while it was busy and runs it in one transaction
   (group commit).
3. It hands each result back to the reader that owns the connection.
4. That reader builds and sends the response, so the writer makes no socket calls.

**One checkpoint thread**, as in the assembly server.

While a connection has a write with the writer, it is paused: nothing more is read or parsed
from it until that response has been sent. Pipelined requests are therefore still answered in order.
Responses are sent only after the commit, as before.

The readers and the writer can be threads or processes:

- **Threads (default).** One process.
  - Readers push jobs onto a lock-free stack and wake the writer with an eventfd, only when the
    stack was empty.
  - Results go back the same way: one list and one wakeup per reader per batch.
- **Processes (`PROCS=1`).** The main process forks one single-threaded reader per core, then
  becomes the writer.
  - Each reader sends its jobs over a `SOCK_SEQPACKET` socket pair.
  - Each batch, the writer sends every reader one message with that reader's results.
  - Connections and their fds stay in the reader that accepted them.
  - Readers are forked before the writer opens the database, so no SQLite connection crosses a `fork()`.

Two settings matter for speed (see the results):

| Variable | Effect |
|---|---|
| `COMMIT_GAP_US` | The writer starts a batch at most this often (5000 = every 5 ms). Writes wait up to that long. Default 0. |
| `READER_MMAP` | `mmap_size` of the reader connections. `0` makes them read with `pread`. Default 1 GB. |

Parsing, JSON, JWT checks and response bytes follow the assembly submission one for one:

- `test/test.sh` passes (42/42), in both modes and with both settings.
- In a 76-case byte-for-byte comparison with the assembly server, no response differed. The
  cases cover odd JSON, Unicode escapes, JWT edge cases, pipelining, `Connection: close`, and
  requests split across packets.

```bash
bash build.sh       # downloads the pinned SQLite amalgamation, builds bin/server
SQLITE_PATH=feed.db PORT=80 HOST=0.0.0.0 COMMIT_GAP_US=5000 READER_MMAP=0 bin/server
```

## Results

Setup:

- **Machine:** the 8-vCPU x86-64 KVM server from `asm-multicore` (AMD EPYC-Milan, Ubuntu 24.04,
  kernel 6.8). The server was pinned to 3 cores, with no fd limit.
- **Load:** the `asm-multicore` load generator on 4 other cores, about 24k connections per
  source address, over loopback in the server's network namespace.
- **Timing:** 90 s ramp, then a 2-minute hold. Every run had 0 errors.

✓/✗ use the challenge's pass limits: p95 under 500 ms and p99 under 1 s. "Gap + no mmap" means
`COMMIT_GAP_US=5000 READER_MMAP=0`.

| Server (3 cores) | Users | p95 | p99 | Server CPU |
|---|---|---|---|---|
| Assembly, 3 processes (`asm-multicore`) | 256,000 | 28–31 ms | 61–92 ms | 146% |
| C threads | 256,000 | 1.6–1.9 ms | 6.5–41 ms | 202% |
| Assembly, 3 processes | 384,000 | 682–707 ms ✗ | 980–1,023 ms ✗ | 151% |
| C threads | 384,000 | 251–291 ms ✓ | 406–415 ms ✓ | 255% |
| C threads, `COMMIT_GAP_US=5000` | 384,000 | 4.9–5.7 ms | 17–122 ms | 196% |
| C threads, `READER_MMAP=0` | 384,000 | 3.6–5.1 ms | 17–139 ms | 221% |
| C threads, gap + no mmap | 384,000 | 4.0–5.1 ms | 15–97 ms | **181%** |
| C processes | 384,000 | 13–16 ms | 32–173 ms | 269% |
| C threads | 448,000 | 646–657 ms ✗ | 855–863 ms | 255% |
| C threads | 512,000 | 716–735 ms ✗ | 970–981 ms | 254% |
| **C threads, gap + no mmap** | **512,000** | **25–37 ms** ✓ | **71–315 ms** ✓ | 230% |
| **C processes, gap + no mmap** | **512,000** | **28–53 ms** ✓ | **136–319 ms** ✓ | 237% |

At 512k the load generator used about 356% of its 4 cores, so I didn't go higher: past that,
the measurement would be about the generator, not the server.

### What limited the first version

At 384k the first version was CPU-bound. A `perf` profile of its three cores during the hold showed:

- **61.7% of its time was in the kernel; its own code and SQLite took 31%.** The hot kernel
  functions were about page mappings:
  - unmapping: `zap_pte_range`, `folio_remove_rmap_ptes`;
  - faulting pages back in: `filemap_map_pages`, `set_pte_range`;
  - TLB shootdowns to the other cores: `smp_call_function_many_cond`;
  - `mmap_lock` contention between threads: `rwsem_optimistic_spin`.
- **The counts during 10 s of the hold** (about 40k requests/s):
  - about 3,300 `munmap` + `mmap` pairs per second;
  - about 52,600 page faults per second, all from SQLite reading b-tree pages (`btreeInitPage`).

The cause is in SQLite. When a connection starts a read transaction and sees that the WAL has
changed, it drops its page cache and unmaps the whole database mapping. The next reads fault the
pages back in. The writer committed about 1,100 times per second, and each of the three readers
remapped once per commit: 3 × 1,100 ≈ 3,300, as counted.

In a multi-threaded process, each `munmap` also interrupts the other cores to flush their TLBs.

The assembly server didn't pay this:
- In one process, its own commits don't count as a change to the WAL.
- With three processes, each has its own address space, so there are no cross-core TLB flushes.

The two settings each remove part of the cost:

- **`COMMIT_GAP_US=5000`** caps commits at 200 per second, so readers remap about 6 times less
  often. Each write waits up to 5 ms more. At 384k, p95 drops from about 270 ms to about 5 ms.
- **`READER_MMAP=0`** removes mapping and unmapping. Readers use `pread` instead: about 175k
  calls per second without the gap, 47k with it.

Together they took CPU at 384k from 255% to 181%, and the server passed 512k.

### Threads or processes

- **Without the settings, processes beat threads.** At 384k, p95 was 13–16 ms against about
  270 ms. Each reader process unmaps only its own address space, so no other core is interrupted.
  CPU was higher (269% against 255%). The extra time probably goes to the socket messages to and
  from the writer process, but I didn't profile that run.
- **With the settings, they are about the same.** Threads were slightly better at 512k: p95
  25–37 ms against 28–53 ms, and CPU 230% against 237%.

Once the remapping is gone, threads have no remaining disadvantage, and they need no messages
between processes.
