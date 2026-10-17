# Breaking the rules: how far the assembly server goes with more cores and no fd limit

This branch is an experiment, not a submission. The submission in
[`submissions/asm-epoll-umitaltintas`](../../submissions/asm-epoll-umitaltintas) follows the rules: one
vCPU, `LimitNOFILE=65535`, and keep-alive budgets so that clients past the fd limit are still
served. Here I drop those limits to see what the same code does with more room. Nothing here
should be compared with challenge scores.

## What changes

Building with `-DUNLEASHED` (see `src/server.asm`) adds two things:

- **`SO_REUSEPORT` on the listen socket.** Several independent server processes share port 80,
  and the kernel spreads connections across them. Each process has its own epoll loop, its own
  SQLite connection and its own checkpoint thread. They share the database file through WAL.
- **`BEGIN IMMEDIATE`** for the write transaction. Each process collects a batch's writes into one
  transaction (group commit), as in the submission, and takes the write lock up front.

The fd limit and the keep-alive budgets are lifted at build time:
`-DMAXCONN=1048576 -DKA_LIMIT=1000000 -DKA_PER_IP=1000000`, with the server run under
`nofile=1048576`.

Example build:

```bash
nasm -f elf64 -O2 -DUNLEASHED -DMAXCONN=1048576 -DKA_LIMIT=1000000 -DKA_PER_IP=1000000 \
  -I src/ -o build/server.o src/server.asm
gcc -no-pie -o bin/server-unleashed build/server.o build/sqlite3.o -lpthread -lm
for i in 1 2 3; do bin/server-unleashed & done   # three processes on one port
```

## Load generator

[`loadgen/`](loadgen) is a Go reimplementation of `bench/load.js`: the same user loop, think
times and probabilities.
- **Design:** Virtual users are small state machines in timer heaps. A fixed pool of 1,024 workers
  runs the next request of each user that is due, using buffers owned by the worker.
- **Memory:** At 192k users it used 1.36 GB in total. The first version, with one goroutine per
  user, used about 8.8 GB, and gave the same latencies on the same run.
- **Lag:** It reports how late due users were picked up. If that grows, the generator is the
  bottleneck and the latencies are not about the server.
- **Source addresses:** `-src` connects from a given local address, so several generator processes
  look like several client machines. It sets `IP_BIND_ADDRESS_NO_PORT`, so the port is chosen at
  `connect()`. Even so, keep it at about 24k connections per source address: much above that, the
  kernel's port search gets expensive and loads the whole host.

## Results

The server ran on an 8-vCPU x86-64 KVM server (AMD EPYC-Milan, Ubuntu 24.04, kernel 6.8), pinned to
the cores shown, with the database on local disk. The load generators ran on other cores of the
same machine and connected over loopback, inside the server's network namespace. There was no
network card in between. 90 s ramp, 2 min hold.

| Build | Cores | Users | Errors | p95 | p99 | Server CPU |
|---|---|---|---|---|---|---|
| Submission (rules: 1 vCPU, 65,535 fds) | 1 | 192,000 | 0 | 54–57 ms | 83–89 ms | 95% |
| Unleashed, 1 process (no fd limit) | 1 | 192,000 | 0 | 36–40 ms | 62–71 ms | 71–73% |
| Unleashed, 3 processes | 3 | 256,000 | 0 | 28–31 ms | 61–92 ms | 146% (≈49% per core) |
| Unleashed, 3 processes | 3 | 384,000 | 0 | **~640–690 ms** | ~940–1,020 ms | 150% (≈50% per core) |

What they show:

- **The fd limit costs about a fifth of a core at 192k.** Under the rules, users past 60,000
  connections get one request per connection, so 132k of them open a new connection for every
  request. Without the limit everyone keeps their connection: server CPU drops from 95% to about
  72%, and latency drops too. The price is memory for the extra open sockets: about 310 MB for the
  container instead of about 110 MB.
- **More processes scale until the SQLite write lock is the limit.** Three processes passed 256k
  at about half a core each. At 384k they failed the latency limits while each core was still
  only about half busy. Each process holds the write lock while it handles the rest of its batch,
  and a process waiting for the lock stops its whole event loop. Building SQLite with
  `HAVE_USLEEP`, so the wait is milliseconds instead of a whole second, didn't change the result.

### A fix that made it worse

The obvious fix is to hold the lock for less time: commit each write right after it runs, and
wait 20 µs for a busy lock instead of SQLite's default sleep. With three processes on three cores
under Rosetta on an Apple Silicon Mac, at 128k users:

| Writes | p95 | p99 | Server CPU |
|---|---|---|---|
| Group commit per batch (this branch) | 7–8 ms | 45–56 ms | 79% |
| One commit per write, 20 µs busy wait | 169–173 ms | ~377 ms | 83% |

Group commit takes the lock and commits once for a whole batch of writes. Committing every write
on its own multiplies the lock handoffs, and the processes wait for each other more, not less.
Spinning on `sched_yield` instead of the 20 µs sleep was worse still: it burned the cores. That
change is not in this branch.

The fix that keeps group commit is a single writer: one process owns all writes and commits them
in batches, and the others only read. That needs a queue between processes, and a way to send
each write's response back on the right connection. I haven't built it. The load where it would
matter (around 384k) is beyond what I can generate on my laptop, so I couldn't measure it anyway.
