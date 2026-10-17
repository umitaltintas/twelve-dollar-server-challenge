// The $12 server challenge API in C, built to scale across cores (experiment, not a submission).
//
// Threads:
//   - N reader threads. Each has its own SO_REUSEPORT listen socket, its own epoll loop and its own
//     SQLite connection. They parse requests, check JWTs, validate bodies and serve every read
//     (GET /feed, /posts/:id, /health) themselves. WAL readers never wait for each other or for the writer.
//   - One writer thread. It owns the only connection that writes. Readers hand it POST /posts and
//     likes through a lock-free queue and wake it with an eventfd. It runs everything that queued up
//     while it was busy in one transaction (group commit), then hands each result back to the reader
//     that owns the connection, which builds and sends the response.
//   - One checkpoint thread, as in the assembly server.
// A connection with a write in flight is paused: nothing more is read or parsed from it until the
// write's response has been sent, so pipelined requests are still answered in order.
//
// Request parsing, JSON, JWT and response bytes follow the assembly submission
// (submissions/asm-epoll-umitaltintas) one for one.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "sqlite3.h"

#define MAX_REQ 32768          // bigger requests are rejected
#define SCRATCH_SZ 65536       // one read lands here
#define BODY_SZ 131072         // one response body is built here
#define MAXEV 1024
#define CKPT_BG_FRAMES 128     // background checkpoint at this many WAL frames
#define CKPT_MAIN_FRAMES 4096  // the writer finishes the checkpoint itself at this size

// ---------------------------------------------------------------------------
// shared state

typedef struct conn {
  char *in;          // leftover input (malloc) or NULL
  char *out;         // unsent output (malloc) or NULL
  uint32_t inlen, outlen, outoff;
  uint8_t alive;
  uint8_t waiting;   // a write job for this connection is with the writer
  uint8_t dead;      // closed while waiting: the fd is released when the job comes back
  uint8_t close_after;
  uint8_t pending_in; // input may be waiting in the socket (an edge arrived while paused)
} conn;

typedef struct worker worker;

typedef struct job {
  struct job *next;
  worker *w;
  conn *c;
  int fd;
  int kind;          // 1 create post, 2 like
  int close;         // Connection: close
  int status;        // result: 200, 201, 404, 500, or -1 if the transaction did not commit
  int64_t uid, pid, id;
  int clen, nlen, blen;
  char created[40];
  char data[];       // username, then body
} job;

struct worker {
  int id, epfd, lfd, evfd, accept_off;
  _Atomic(job *) done;         // results from the writer
  sqlite3 *db;
  sqlite3_stmt *st_feed, *st_post, *st_one;
  time_t now;
  // the request being handled
  int fd;
  conn *c;
  int method;
  const char *path, *rbody, *auth;
  size_t plen, blen, alen;
  int rclose;
  int64_t uid;
  const char *name;
  size_t nlen;
  // output for the connection being handled
  char *out;
  size_t outlen, outcap;
  char scratch[SCRATCH_SZ + 64];
  char body[BODY_SZ];
  char strbuf[SCRATCH_SZ];
  char keybuf[SCRATCH_SZ];
  char hdrbuf[1024], plbuf[4096], subbuf[4096], namebuf[4096];
};

static conn *conns;
static size_t maxconn;
static worker **workers;
static int nworkers;
static const char *db_path;
static time_t start_time;
static struct sockaddr_in listen_addr;
static _Atomic(job *) wq;      // jobs for the writer
static int wq_evfd;
static atomic_int wal_frames;

// ---------------------------------------------------------------------------
// SHA-256 / HMAC

typedef struct { uint32_t h[8]; uint64_t n; uint8_t buf[64]; size_t blen; } sha256;

static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_compress(uint32_t *h, const uint8_t *p) {
  uint32_t w[64], a, b, c, d, e, f, g, hh;
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
    uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static const uint32_t SHA_IV[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

static void sha_update(sha256 *s, const void *data, size_t len) {
  const uint8_t *p = data;
  s->n += len;
  if (s->blen) {
    size_t k = 64 - s->blen;
    if (k > len) k = len;
    memcpy(s->buf + s->blen, p, k);
    s->blen += k; p += k; len -= k;
    if (s->blen < 64) return;
    sha_compress(s->h, s->buf);
    s->blen = 0;
  }
  for (; len >= 64; p += 64, len -= 64) sha_compress(s->h, p);
  memcpy(s->buf, p, len);
  s->blen = len;
}

static void sha_final(sha256 *s, uint8_t out[32]) {
  uint64_t bits = s->n * 8;
  uint8_t pad = 0x80;
  sha_update(s, &pad, 1);
  pad = 0;
  while (s->blen != 56) sha_update(s, &pad, 1);
  uint8_t l[8];
  for (int i = 0; i < 8; i++) l[i] = bits >> (56 - 8 * i);
  sha_update(s, l, 8);
  for (int i = 0; i < 8; i++) {
    out[4 * i] = s->h[i] >> 24; out[4 * i + 1] = s->h[i] >> 16;
    out[4 * i + 2] = s->h[i] >> 8; out[4 * i + 3] = s->h[i];
  }
}

static uint32_t hmac_istate[8], hmac_ostate[8];

static void hmac_init(const char *key, size_t klen) {
  uint8_t k[64] = {0}, b[64];
  if (klen > 64) {
    sha256 s = {.n = 0, .blen = 0};
    memcpy(s.h, SHA_IV, 32);
    sha_update(&s, key, klen);
    sha_final(&s, k);
  } else {
    memcpy(k, key, klen);
  }
  for (int i = 0; i < 64; i++) b[i] = k[i] ^ 0x36;
  memcpy(hmac_istate, SHA_IV, 32);
  sha_compress(hmac_istate, b);
  for (int i = 0; i < 64; i++) b[i] = k[i] ^ 0x5c;
  memcpy(hmac_ostate, SHA_IV, 32);
  sha_compress(hmac_ostate, b);
}

static void hmac_sha256(const void *msg, size_t len, uint8_t out[32]) {
  sha256 s = {.n = 64, .blen = 0};
  memcpy(s.h, hmac_istate, 32);
  sha_update(&s, msg, len);
  uint8_t inner[32];
  sha_final(&s, inner);
  s.n = 64; s.blen = 0;
  memcpy(s.h, hmac_ostate, 32);
  sha_update(&s, inner, 32);
  sha_final(&s, out);
}

// ---------------------------------------------------------------------------
// base64url, JSON reading (strict RFC 8259) and writing

static uint8_t b64tab[256];

static void b64_init(void) {
  memset(b64tab, 0xFF, sizeof b64tab);
  int v = 0;
  for (int c = 'A'; c <= 'Z'; c++) b64tab[c] = v++;
  for (int c = 'a'; c <= 'z'; c++) b64tab[c] = v++;
  for (int c = '0'; c <= '9'; c++) b64tab[c] = v++;
  b64tab['-'] = 62; b64tab['_'] = 63;
}

// base64url without padding -> bytes written, or -1
static long b64d(const char *s, size_t len, uint8_t *out) {
  if ((len & 3) == 1) return -1;
  uint32_t acc = 0;
  int bits = 0;
  uint8_t *o = out;
  for (size_t i = 0; i < len; i++) {
    uint8_t v = b64tab[(uint8_t)s[i]];
    if (v == 0xFF) return -1;
    acc = acc << 6 | v;
    bits += 6;
    if (bits >= 8) { bits -= 8; *o++ = acc >> bits; }
  }
  return o - out;
}

static const char *jws(const char *p, const char *e) {
  while (p < e && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) p++;
  return p;
}

static int hex4(const char *p, const char *e, uint32_t *v) {
  if (p + 4 > e) return -1;
  uint32_t r = 0;
  for (int i = 0; i < 4; i++) {
    int c = (uint8_t)p[i], d;
    if (c >= '0' && c <= '9') d = c - '0';
    else {
      c |= 0x20;
      if (c < 'a' || c > 'f') return -1;
      d = c - 'a' + 10;
    }
    r = r << 4 | d;
  }
  *v = r;
  return 0;
}

static char *put_utf8(char *o, uint32_t cp) {
  if (cp < 0x80) { *o++ = cp; }
  else if (cp < 0x800) { *o++ = 0xC0 | cp >> 6; *o++ = 0x80 | (cp & 0x3F); }
  else if (cp < 0x10000) { *o++ = 0xE0 | cp >> 12; *o++ = 0x80 | (cp >> 6 & 0x3F); *o++ = 0x80 | (cp & 0x3F); }
  else { *o++ = 0xF0 | cp >> 18; *o++ = 0x80 | (cp >> 12 & 0x3F); *o++ = 0x80 | (cp >> 6 & 0x3F); *o++ = 0x80 | (cp & 0x3F); }
  return o;
}

// p at the opening quote. Decodes into out (NULL: validate only). Returns the end of the
// string (after the quote) or NULL; *olen gets the decoded length.
static const char *jstr(const char *p, const char *e, char *out, size_t *olen) {
  char tmp[4];
  size_t k = 0;
  p++;
  for (;;) {
    if (p >= e) return NULL;
    uint8_t c = *p;
    if (c == '"') { p++; break; }
    if (c < 0x20) return NULL;
    if (c != '\\') { if (out) out[k] = c; k++; p++; continue; }
    p++;
    if (p >= e) return NULL;
    c = *p++;
    char ch;
    switch (c) {
      case '"': case '\\': case '/': ch = c; break;
      case 'b': ch = 8; break;
      case 'f': ch = 12; break;
      case 'n': ch = 10; break;
      case 'r': ch = 13; break;
      case 't': ch = 9; break;
      case 'u': {
        uint32_t cp, lo;
        if (hex4(p, e, &cp)) return NULL;
        p += 4;
        if (cp >= 0xD800 && cp <= 0xDBFF && p + 6 <= e && p[0] == '\\' && p[1] == 'u' &&
            !hex4(p + 2, e, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
          cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          p += 6;
        }
        char *d = out ? out + k : tmp;
        k += put_utf8(d, cp) - d;
        continue;
      }
      default: return NULL;
    }
    if (out) out[k] = ch;
    k++;
  }
  if (olen) *olen = k;
  return p;
}

static const char *jdigits(const char *p, const char *e) {
  while (p < e && *p >= '0' && *p <= '9') p++;
  return p;
}

// validate and skip one value
static const char *jskip(const char *p, const char *e, int depth) {
  if (p >= e) return NULL;
  char c = *p;
  if (c == '"') return jstr(p, e, NULL, NULL);
  if (c == '{' || c == '[') {
    if (++depth > 256) return NULL;
    char close = c == '{' ? '}' : ']';
    p = jws(p + 1, e);
    if (p >= e) return NULL;
    if (*p == close) return p + 1;
    for (;;) {
      if (c == '{') {
        if (p >= e || *p != '"') return NULL;
        p = jstr(p, e, NULL, NULL);
        if (!p) return NULL;
        p = jws(p, e);
        if (p >= e || *p != ':') return NULL;
        p = jws(p + 1, e);
      }
      p = jskip(p, e, depth);
      if (!p) return NULL;
      p = jws(p, e);
      if (p >= e) return NULL;
      char d = *p++;
      if (d == close) return p;
      if (d != ',') return NULL;
      p = jws(p, e);
    }
  }
  if (c == '-' || (c >= '0' && c <= '9')) {
    if (c == '-' && ++p >= e) return NULL;
    if (*p == '0') p++;
    else if (*p >= '1' && *p <= '9') p = jdigits(p, e);
    else return NULL;
    if (p < e && *p == '.') {
      p++;
      if (p >= e || *p < '0' || *p > '9') return NULL;
      p = jdigits(p, e);
    }
    if (p < e && (*p | 0x20) == 'e') {
      p++;
      if (p >= e) return NULL;
      if (*p == '+' || *p == '-') p++;
      if (p >= e || *p < '0' || *p > '9') return NULL;
      p = jdigits(p, e);
    }
    return p;
  }
  static const char *lits[] = {"true", "false", "null"};
  for (int i = 0; i < 3; i++) {
    size_t n = strlen(lits[i]);
    if (c == lits[i][0]) return (p + n <= e && !memcmp(p, lits[i], n)) ? p + n : NULL;
  }
  return NULL;
}

// Validate a whole document. If it is an object, vals[i] gets where the value of keys[i]
// starts (last one wins, NULL if absent). Returns -1 invalid, 1 object, 0 other valid JSON.
static int obj_scan(worker *w, const char *p, const char *e, const char *const *keys, int nk, const char **vals) {
  for (int i = 0; i < nk; i++) vals[i] = NULL;
  p = jws(p, e);
  if (p >= e) return -1;
  if (*p != '{') {
    p = jskip(p, e, 0);
    if (!p) return -1;
    return jws(p, e) == e ? 0 : -1;
  }
  p = jws(p + 1, e);
  if (p >= e) return -1;
  if (*p == '}') return jws(p + 1, e) == e ? 1 : -1;
  for (;;) {
    if (p >= e || *p != '"') return -1;
    size_t klen;
    p = jstr(p, e, w->keybuf, &klen);
    if (!p) return -1;
    p = jws(p, e);
    if (p >= e || *p != ':') return -1;
    p = jws(p + 1, e);
    if (p >= e) return -1;
    for (int i = 0; i < nk; i++)
      if (strlen(keys[i]) == klen && !memcmp(keys[i], w->keybuf, klen)) vals[i] = p;
    p = jskip(p, e, 0);
    if (!p) return -1;
    p = jws(p, e);
    if (p >= e) return -1;
    char d = *p++;
    if (d == '}') return jws(p, e) == e ? 1 : -1;
    if (d != ',') return -1;
    p = jws(p, e);
  }
}

static char *w_u64(char *o, uint64_t v) {
  char t[24];
  int n = 0;
  do { t[n++] = '0' + v % 10; v /= 10; } while (v);
  while (n) *o++ = t[--n];
  return o;
}

static char *w_lit(char *o, const char *s) {
  size_t n = strlen(s);
  memcpy(o, s, n);
  return o + n;
}

// quoted JSON string, escaped like JSON.stringify
static char *w_jstr(char *o, const char *s, size_t n) {
  static const char ctl[16] = {0, 0, 0, 0, 0, 0, 0, 0, 'b', 't', 'n', 0, 'f', 'r', 0, 0};
  static const char hex[] = "0123456789abcdef";
  *o++ = '"';
  for (size_t i = 0; i < n; i++) {
    uint8_t c = s[i];
    if (c == '"' || c == '\\') { *o++ = '\\'; *o++ = c; }
    else if (c < 0x20) {
      if (c < 16 && ctl[c]) { *o++ = '\\'; *o++ = ctl[c]; }
      else { memcpy(o, "\\u00", 4); o[4] = hex[c >> 4]; o[5] = hex[c & 15]; o += 6; }
    } else *o++ = c;
  }
  *o++ = '"';
  return o;
}

// JavaScript String.prototype.trim() whitespace
static int ws_at(const uint8_t *p, const uint8_t *e) {
  size_t n = e - p;
  if (!n) return 0;
  uint8_t c = p[0];
  if (c == ' ' || (c >= 9 && c <= 13)) return 1;
  if (n >= 2 && c == 0xC2 && p[1] == 0xA0) return 2;
  if (n < 3) return 0;
  uint32_t v = (uint32_t)p[0] << 16 | p[1] << 8 | p[2];
  if (v == 0xE19A80 || v == 0xE2819F || v == 0xE38080 || v == 0xEFBBBF) return 3;
  if ((v >> 8) == 0xE280) {
    uint8_t t = v & 0xFF;
    if (t == 0xA8 || t == 0xA9 || t == 0xAF || (t >= 0x80 && t <= 0x8A)) return 3;
  }
  return 0;
}

static int ws_before(const uint8_t *s, const uint8_t *e) {
  size_t n = e - s;
  if (!n) return 0;
  uint8_t c = e[-1];
  if (c == ' ' || (c >= 9 && c <= 13)) return 1;
  if (n >= 2 && e[-2] == 0xC2 && c == 0xA0) return 2;
  if (n >= 3 && ws_at(e - 3, e) == 3) return 3;
  return 0;
}

// ---------------------------------------------------------------------------
// output

static void out_reserve(worker *w, size_t n) {
  if (w->outlen + n <= w->outcap) return;
  size_t cap = w->outcap ? w->outcap : 65536;
  while (cap < w->outlen + n) cap *= 2;
  w->out = realloc(w->out, cap);
  w->outcap = cap;
}

static const char *const status_line[] = {
  [200] = "HTTP/1.1 200 OK\r\n", [201] = "HTTP/1.1 201 Created\r\n",
  [400] = "HTTP/1.1 400 Bad Request\r\n", [401] = "HTTP/1.1 401 Unauthorized\r\n",
  [404] = "HTTP/1.1 404 Not Found\r\n", [500] = "HTTP/1.1 500 Internal Server Error\r\n",
  [503] = "HTTP/1.1 503 Service Unavailable\r\n"};

// queue one response (body in w->body up to bend) for the current connection
static void emit(worker *w, int st, const char *bend, int close) {
  size_t blen = bend - w->body;
  out_reserve(w, blen + 160);
  char *o = w->out + w->outlen;
  o = w_lit(o, status_line[st]);
  o = w_lit(o, "Content-Type: application/json\r\nContent-Length: ");
  o = w_u64(o, blen);
  if (close) o = w_lit(o, "\r\nConnection: close");
  o = w_lit(o, "\r\n\r\n");
  memcpy(o, w->body, blen);
  w->outlen = o + blen - w->out;
}

static void reply(worker *w, int st, const char *body) {
  emit(w, st, w_lit(w->body, body), w->rclose);
}

// ---------------------------------------------------------------------------
// connections

static void ep_mod(worker *w, int fd, uint32_t ev) {
  struct epoll_event e = {.events = ev, .data.fd = fd};
  epoll_ctl(w->epfd, EPOLL_CTL_MOD, fd, &e);
}

static void conn_release(worker *w, int fd, conn *c) {
  // Clear the record before close(): once the fd is closed, another reader thread can
  // accept a new connection with the same number and set up conns[fd] for it.
  free(c->in);
  free(c->out);
  memset(c, 0, sizeof *c);
  close(fd);
  if (w->accept_off) {      // an fd is free again
    w->accept_off = 0;
    ep_mod(w, w->lfd, EPOLLIN);
  }
}

static void conn_close(worker *w, int fd, conn *c) {
  if (!c->alive) return;
  if (c->waiting) { c->dead = 1; return; }  // keep the fd until the writer is done with it
  conn_release(w, fd, c);
}

static int resumable(conn *c) {
  return c->alive && !c->dead && !c->waiting && c->outlen == 0;
}

static void stash(conn *c, const char *p, size_t n) {
  char *b = malloc(n);
  memcpy(b, p, n);
  free(c->in);
  c->in = b;
  c->inlen = n;
}

static size_t take_stash(worker *w, conn *c) {
  if (!c->in) return 0;
  size_t n = c->inlen;
  memcpy(w->scratch, c->in, n);
  free(c->in);
  c->in = NULL;
  c->inlen = 0;
  return n;
}

// send (or queue behind pending output); close afterwards if asked
static void conn_send(worker *w, int fd, conn *c, const char *p, size_t n, int close_after) {
  if (c->outlen) {
    c->out = realloc(c->out, c->outlen + n);
    memcpy(c->out + c->outlen, p, n);
    c->outlen += n;
    c->close_after |= close_after;
    return;
  }
  // A closing response is held back (MSG_MORE) so close() sends the FIN on the same segment.
  ssize_t s = send(fd, p, n, MSG_NOSIGNAL | (close_after ? MSG_MORE : 0));
  if (s == (ssize_t)n) {
    if (close_after) conn_close(w, fd, c);
    return;
  }
  if (s < 0) {
    if (errno != EAGAIN) { conn_close(w, fd, c); return; }
    s = 0;
  }
  c->out = malloc(n - s);
  memcpy(c->out, p + s, n - s);
  c->outlen = n - s;
  c->outoff = 0;
  c->close_after = close_after;
}

// ---------------------------------------------------------------------------
// auth

// 0 ok (w->uid, w->name set), 1 missing bearer, 2 invalid or expired, 3 invalid payload
static int auth_check(worker *w) {
  const char *a = w->auth;
  size_t n = w->alen;
  if (!a || n < 7 || memcmp(a, "Bearer ", 7)) return 1;
  const char *t = a + 7, *e = a + n;
  const char *d1 = memchr(t, '.', e - t);
  if (!d1) return 2;
  const char *d2 = memchr(d1 + 1, '.', e - d1 - 1);
  if (!d2) return 2;
  uint8_t sig[48], mac[32];
  if (e - (d2 + 1) != 43 || b64d(d2 + 1, 43, sig) != 32) return 2;
  hmac_sha256(t, d2 - t, mac);
  uint8_t diff = 0;
  for (int i = 0; i < 32; i++) diff |= sig[i] ^ mac[i];
  if (diff) return 2;
  // header: alg must be "HS256"
  if (d1 - t > 1024) return 2;
  long hl = b64d(t, d1 - t, (uint8_t *)w->hdrbuf);
  if (hl < 0) return 2;
  static const char *const hk[] = {"alg"};
  const char *hv[1];
  if (obj_scan(w, w->hdrbuf, w->hdrbuf + hl, hk, 1, hv) != 1 || !hv[0] || *hv[0] != '"') return 2;
  size_t alg_len;
  jstr(hv[0], w->hdrbuf + hl, w->subbuf, &alg_len);
  if (alg_len != 5 || memcmp(w->subbuf, "HS256", 5)) return 2;
  // payload
  if (d2 - (d1 + 1) > 4096) return 2;
  long pl = b64d(d1 + 1, d2 - (d1 + 1), (uint8_t *)w->plbuf);
  if (pl < 0) return 2;
  const char *pe = w->plbuf + pl;
  static const char *const pk[] = {"sub", "username", "exp"};
  const char *pv[3];
  if (obj_scan(w, w->plbuf, pe, pk, 3, pv) != 1) return 2;
  if (pv[2]) {  // exp (optional): a number in the future
    const char *p = pv[2];
    if (*p < '0' || *p > '9') return 2;
    int64_t exp = 0;
    int nd = 0, far = 0;
    for (; p < pe && *p >= '0' && *p <= '9'; p++) {
      if (++nd > 18) { far = 1; break; }
      exp = exp * 10 + (*p - '0');
    }
    if (!far && exp <= w->now) return 2;
  }
  if (!pv[0] || *pv[0] != '"') return 3;
  size_t sl;
  jstr(pv[0], pe, w->subbuf, &sl);
  if (sl == 0 || sl > 18) return 3;
  int64_t uid = 0;
  for (size_t i = 0; i < sl; i++) {
    unsigned dgt = (uint8_t)w->subbuf[i] - '0';
    if (dgt > 9) return 3;
    uid = uid * 10 + dgt;
  }
  if (!uid) return 3;
  if (!pv[1] || *pv[1] != '"') return 3;
  size_t nl;
  jstr(pv[1], pe, w->namebuf, &nl);
  w->uid = uid;
  w->name = w->namebuf;
  w->nlen = nl;
  return 0;
}

static int do_auth(worker *w) {
  int r = auth_check(w);
  if (r == 1) reply(w, 401, "{\"error\":\"missing bearer token\"}");
  else if (r == 2) reply(w, 401, "{\"error\":\"invalid or expired token\"}");
  else if (r == 3) reply(w, 401, "{\"error\":\"invalid token payload\"}");
  return r;
}

// ---------------------------------------------------------------------------
// handlers. Each either queues one response (returns 0) or hands a job to the writer (returns 1).

static char *write_post(sqlite3_stmt *st, char *o) {
  o = w_lit(o, "{\"id\":");
  o = w_u64(o, sqlite3_column_int64(st, 0));
  o = w_lit(o, ",\"body\":");
  o = w_jstr(o, (const char *)sqlite3_column_text(st, 1), sqlite3_column_bytes(st, 1));
  o = w_lit(o, ",\"created_at\":");
  o = w_jstr(o, (const char *)sqlite3_column_text(st, 2), sqlite3_column_bytes(st, 2));
  o = w_lit(o, ",\"author\":");
  o = w_jstr(o, (const char *)sqlite3_column_text(st, 3), sqlite3_column_bytes(st, 3));
  o = w_lit(o, ",\"like_count\":");
  o = w_u64(o, sqlite3_column_int64(st, 4));
  *o++ = '}';
  return o;
}

static int h_feed(worker *w) {
  sqlite3_stmt *st = w->st_feed;
  char *o = w_lit(w->body, "{\"posts\":[");
  int n = 0, rc;
  while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
    if (n++) *o++ = ',';
    o = write_post(st, o);
  }
  sqlite3_reset(st);
  if (rc != SQLITE_DONE) { reply(w, 500, "{\"error\":\"internal server error\"}"); return 0; }
  o = w_lit(o, "]}");
  emit(w, 200, o, w->rclose);
  return 0;
}

static int h_get_post(worker *w, int64_t id) {
  sqlite3_stmt *st = w->st_post;
  sqlite3_bind_int64(st, 1, id);
  int rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    char *o = w_lit(w->body, "{\"post\":");
    o = write_post(st, o);
    *o++ = '}';
    sqlite3_reset(st);
    emit(w, 200, o, w->rclose);
    return 0;
  }
  sqlite3_reset(st);
  if (rc == SQLITE_DONE) reply(w, 404, "{\"error\":\"post not found\"}");
  else reply(w, 500, "{\"error\":\"internal server error\"}");
  return 0;
}

static int h_health(worker *w) {
  int rc = sqlite3_step(w->st_one);
  sqlite3_reset(w->st_one);
  char *o;
  if (rc == SQLITE_ROW) {
    o = w_lit(w->body, "{\"status\":\"ok\",\"db\":\"ok\",\"uptime_s\":");
    o = w_u64(o, w->now - start_time);
    *o++ = '}';
    emit(w, 200, o, w->rclose);
  } else {
    const char *m = sqlite3_errmsg(w->db);
    o = w_lit(w->body, "{\"status\":\"degraded\",\"db\":\"unreachable\",\"error\":");
    o = w_jstr(o, m, strlen(m));
    *o++ = '}';
    emit(w, 503, o, w->rclose);
  }
  return 0;
}

static void writer_push(job *j) {
  job *old = atomic_load_explicit(&wq, memory_order_relaxed);
  do j->next = old;
  while (!atomic_compare_exchange_weak_explicit(&wq, &old, j, memory_order_release, memory_order_relaxed));
  if (!old) {  // the queue was empty: the writer may be asleep
    uint64_t one = 1;
    (void)!write(wq_evfd, &one, 8);
  }
}

static int queue_job(worker *w, int kind, int64_t pid, const char *body, size_t blen) {
  job *j = malloc(sizeof(job) + w->nlen + blen);
  j->w = w;
  j->c = w->c;
  j->fd = w->fd;
  j->kind = kind;
  j->close = w->rclose;
  j->uid = w->uid;
  j->pid = pid;
  j->nlen = w->nlen;
  j->blen = blen;
  memcpy(j->data, w->name, w->nlen);
  memcpy(j->data + w->nlen, body, blen);
  w->c->waiting = 1;
  writer_push(j);
  return 1;
}

static int h_create(worker *w) {
  if (do_auth(w)) return 0;
  static const char *const bk[] = {"body"};
  const char *bv[1];
  const char *e = w->rbody + w->blen;
  int r = obj_scan(w, w->rbody, e, bk, 1, bv);
  if (r < 0) { reply(w, 400, "{\"error\":\"malformed JSON body\"}"); return 0; }
  if (r == 0 || !bv[0] || *bv[0] != '"') { reply(w, 400, "{\"error\":\"body is required\"}"); return 0; }
  size_t n;
  jstr(bv[0], e, w->strbuf, &n);
  const uint8_t *s = (const uint8_t *)w->strbuf, *t = s + n;
  int k;
  while ((k = ws_at(s, t))) s += k;
  while ((k = ws_before(s, t))) t -= k;
  if (s >= t) { reply(w, 400, "{\"error\":\"body is required\"}"); return 0; }
  size_t chars = 0;
  for (const uint8_t *p = s; p < t; p++) chars += (*p & 0xC0) != 0x80;
  if (chars > 500) { reply(w, 400, "{\"error\":\"body must be at most 500 characters\"}"); return 0; }
  return queue_job(w, 1, 0, (const char *)s, t - s);
}

static int64_t parse_id(const char *p, size_t n) {
  if (!n || n > 18) return 0;
  int64_t v = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned d = (uint8_t)p[i] - '0';
    if (d > 9) return 0;
    v = v * 10 + d;
  }
  return v;
}

static int route(worker *w) {
  const char *p = w->path;
  size_t n = w->plen;
  if (w->method == 1) {
    if (n == 5) {
      if (!memcmp(p, "/feed", 5)) return h_feed(w);
    } else if (n >= 7) {
      if (n == 7 && !memcmp(p, "/health", 7)) return h_health(w);
      if (!memcmp(p, "/posts/", 7) && !memchr(p + 7, '/', n - 7)) {
        int64_t id = parse_id(p + 7, n - 7);
        if (!id) { reply(w, 400, "{\"error\":\"invalid post id\"}"); return 0; }
        return h_get_post(w, id);
      }
    }
  } else if (w->method == 2) {
    if (n == 6) {
      if (!memcmp(p, "/posts", 6)) return h_create(w);
    } else if (n >= 12 && !memcmp(p, "/posts/", 7) && !memcmp(p + n - 5, "/like", 5) &&
               !memchr(p + 7, '/', n - 12)) {
      if (do_auth(w)) return 0;  // auth is checked before the id
      int64_t id = parse_id(p + 7, n - 12);
      if (!id) { reply(w, 400, "{\"error\":\"invalid post id\"}"); return 0; }
      return queue_job(w, 2, id, NULL, 0);
    }
  }
  reply(w, 404, "{\"error\":\"not found\"}");
  return 0;
}

// ---------------------------------------------------------------------------
// HTTP

static int ci_eq(const char *s, const char *lower, size_t n) {
  for (size_t i = 0; i < n; i++)
    if ((s[i] | 0x20) != lower[i]) return 0;
  return 1;
}

// Parse and handle every complete request in buf. Leftovers are stashed, output is sent.
static void process(worker *w, int fd, conn *c, char *buf, size_t len) {
  size_t pos = 0;
  int closing = 0;
  w->outlen = 0;
  w->fd = fd;
  w->c = c;
  while (pos < len) {
    char *s = buf + pos, *end = buf + len;
    char *he = memmem(s, end - s, "\r\n\r\n", 4);
    if (!he) {
      if ((size_t)(end - s) >= MAX_REQ) goto bad;
      break;
    }
    char *body = he + 4, *hend = he + 2;  // hend: end of the last header line
    w->rclose = 0;
    w->blen = 0;
    w->auth = NULL;
    w->alen = 0;
    char *p = s;
    if (!memcmp(p, "GET ", 4)) { w->method = 1; p += 4; }
    else if (!memcmp(p, "POST ", 5)) { w->method = 2; p += 5; }
    else {
      w->method = 0;
      while (p < hend && *p != ' ') p++;
      if (p >= hend) goto bad;
      p++;
    }
    char *q = p;
    while (q < hend && *q != ' ' && *q != '?' && *q != '\r') q++;
    if (q >= hend || q == p) goto bad;
    w->path = p;
    w->plen = q - p;
    while (q < hend && *q != '\n') q++;
    if (q >= hend) goto bad;
    for (char *l = q + 1; l < hend;) {
      char *nl = memchr(l, '\n', hend - l);  // every line before hend ends with '\n'
      char *le = nl;
      if (le > l && le[-1] == '\r') le--;
      char *colon = memchr(l, ':', le - l);
      if (colon) {
        size_t kn = colon - l;
        char *v = colon + 1, *ve = le;
        while (v < ve && (*v == ' ' || *v == '\t')) v++;
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
        if (kn == 14 && ci_eq(l, "content-length", 14)) {
          if (v >= ve) goto bad;
          size_t cl = 0;
          for (; v < ve; v++) {
            unsigned d = (uint8_t)*v - '0';
            if (d > 9) goto bad;
            cl = cl * 10 + d;
            if (cl > MAX_REQ) goto bad;
          }
          w->blen = cl;
        } else if (kn == 13 && ci_eq(l, "authorization", 13)) {
          w->auth = v;
          w->alen = ve - v;
        } else if (kn == 10 && ci_eq(l, "connection", 10)) {
          if (v < ve && (*v | 0x20) == 'c') w->rclose = 1;  // "close"
        }
      }
      l = nl + 1;
    }
    if (body + w->blen > end) {  // body not complete yet
      if ((size_t)(end - s) >= MAX_REQ) goto bad;
      break;
    }
    w->rbody = body;
    pos = body + w->blen - buf;
    int queued = route(w);
    if (w->rclose) { closing = 1; pos = len; break; }  // ignore anything after "Connection: close"
    if (queued) break;
    continue;
  bad:
    w->rclose = 1;
    reply(w, 400, "{\"error\":\"bad request\"}");
    closing = 1;
    pos = len;
    break;
  }
  if (pos < len) stash(c, buf + pos, len - pos);
  int close_now = closing && !c->waiting;  // with a write in flight, its response closes instead
  if (w->outlen) conn_send(w, fd, c, w->out, w->outlen, close_now);
  else if (close_now) conn_close(w, fd, c);
}

// Read and handle until the socket is drained (edge-triggered) or the connection pauses.
// A short read means the socket was empty, unless the peer has also shut down its side
// (until_eagain): then keep reading to see the EOF, since no further edge will come.
static void conn_read(worker *w, int fd, conn *c, int until_eagain) {
  c->pending_in = 0;
  for (;;) {
    size_t have = take_stash(w, c);
    size_t room = SCRATCH_SZ - have;
    if (!room) { conn_close(w, fd, c); return; }
    ssize_t n = read(fd, w->scratch + have, room);
    if (n > 0) {
      process(w, fd, c, w->scratch, have + n);
      if (!c->alive) return;
      int more = until_eagain || (size_t)n == room;
      if (!resumable(c)) { if (more) c->pending_in = 1; return; }
      if (!more) return;
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
      if (have) stash(c, w->scratch, have);
      return;
    }
    conn_close(w, fd, c);  // EOF or error
    return;
  }
}

// the connection can take requests again: handle what it sent meanwhile
static void conn_resume(worker *w, int fd, conn *c) {
  if (c->in) {
    size_t have = take_stash(w, c);
    process(w, fd, c, w->scratch, have);
    if (!resumable(c)) return;
  }
  if (c->pending_in) conn_read(w, fd, c, 1);
}

static void on_writable(worker *w, int fd, conn *c) {
  ssize_t s = send(fd, c->out + c->outoff, c->outlen - c->outoff, MSG_NOSIGNAL);
  if (s < 0) {
    if (errno != EAGAIN) conn_close(w, fd, c);
    return;
  }
  c->outoff += s;
  if (c->outoff < c->outlen) return;
  free(c->out);
  c->out = NULL;
  c->outlen = c->outoff = 0;
  if (c->close_after) {
    c->close_after = 0;
    conn_close(w, fd, c);
    return;
  }
  if (resumable(c)) conn_resume(w, fd, c);
}

// a write came back from the writer
static void complete(worker *w, job *j) {
  conn *c = j->c;
  int fd = j->fd;
  c->waiting = 0;
  if (c->dead || j->status < 0) {  // never acknowledge a write that did not commit
    free(j);
    c->dead = 0;
    conn_release(w, fd, c);
    return;
  }
  w->outlen = 0;
  w->rclose = j->close;
  char *o = w->body;
  int st = j->status;
  if (st == 500) o = w_lit(o, "{\"error\":\"internal server error\"}");
  else if (j->kind == 1) {
    o = w_lit(o, "{\"post\":{\"id\":");
    o = w_u64(o, j->id);
    o = w_lit(o, ",\"body\":");
    o = w_jstr(o, j->data + j->nlen, j->blen);
    o = w_lit(o, ",\"created_at\":");
    o = w_jstr(o, j->created, j->clen);
    o = w_lit(o, ",\"author\":");
    o = w_jstr(o, j->data, j->nlen);
    o = w_lit(o, ",\"like_count\":0}}");
  } else if (st == 404) o = w_lit(o, "{\"error\":\"post not found\"}");
  else {
    o = w_lit(o, st == 201 ? "{\"liked\":true,\"already_liked\":false,\"post_id\":"
                           : "{\"liked\":true,\"already_liked\":true,\"post_id\":");
    o = w_u64(o, j->pid);
    *o++ = '}';
  }
  emit(w, st, o, j->close);
  int close_after = j->close;
  free(j);
  conn_send(w, fd, c, w->out, w->outlen, close_after);
  if (resumable(c)) conn_resume(w, fd, c);
}

static void do_accept(worker *w) {
  for (int i = 0; i < 1024; i++) {
    int fd = accept4(w->lfd, NULL, NULL, SOCK_NONBLOCK);
    if (fd < 0) {
      if (errno == EMFILE || errno == ENFILE) {
        // no fd left: stop polling the listen socket until a connection closes
        w->accept_off = 1;
        ep_mod(w, w->lfd, 0);
      }
      return;
    }
    if ((size_t)fd >= maxconn) { close(fd); continue; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    conn *c = &conns[fd];
    memset(c, 0, sizeof *c);
    c->alive = 1;
    struct epoll_event e = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.fd = fd};
    epoll_ctl(w->epfd, EPOLL_CTL_ADD, fd, &e);
  }
}

// ---------------------------------------------------------------------------
// SQLite

static void die_db(sqlite3 *db, const char *what) {
  fprintf(stderr, "%s: %s\n", what, db ? sqlite3_errmsg(db) : "?");
  exit(1);
}

static sqlite3 *db_open(const char *pragmas) {
  sqlite3 *db;
  if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL)) die_db(db, "open");
  if (sqlite3_exec(db, pragmas, NULL, NULL, NULL)) die_db(db, "pragmas");
  return db;
}

static sqlite3_stmt *prep(sqlite3 *db, const char *sql) {
  sqlite3_stmt *st;
  if (sqlite3_prepare_v3(db, sql, -1, SQLITE_PREPARE_PERSISTENT, &st, NULL)) die_db(db, sql);
  return st;
}

#define POST_COLS "SELECT p.id,p.body,p.created_at,u.username,(SELECT count(*) FROM likes l WHERE l.post_id=p.id) FROM posts p JOIN users u ON u.id=p.user_id "

static int wal_cb(void *arg, sqlite3 *db, const char *name, int frames) {
  (void)arg; (void)db; (void)name;
  atomic_store_explicit(&wal_frames, frames, memory_order_relaxed);
  return 0;
}

// Checkpoints run on their own thread and connection, off the request path. Under constant
// writes they never quite reach the end of the WAL, so the writer finishes the last frames itself.
static void *ckpt_main(void *arg) {
  (void)arg;
  sqlite3 *db = db_open("PRAGMA busy_timeout=5000;PRAGMA mmap_size=1073741824;");
  for (;;) {
    usleep(50000);
    if (atomic_load_explicit(&wal_frames, memory_order_relaxed) >= CKPT_BG_FRAMES)
      sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
  }
  return NULL;
}

static sqlite3 *wdb;

static void *writer_main(void *arg) {
  (void)arg;
  sqlite3_stmt *st_ins = prep(wdb, "INSERT INTO posts(user_id,body) VALUES(?1,?2) RETURNING id,created_at");
  sqlite3_stmt *st_like = prep(wdb, "INSERT INTO likes(user_id,post_id) SELECT ?1,?2 "
                                    "WHERE EXISTS(SELECT 1 FROM posts WHERE id=?2) ON CONFLICT DO NOTHING");
  sqlite3_stmt *st_exists = prep(wdb, "SELECT 1 FROM posts WHERE id=?1");
  sqlite3_stmt *st_begin = prep(wdb, "BEGIN IMMEDIATE");
  sqlite3_stmt *st_commit = prep(wdb, "COMMIT");
  job **heads = calloc(nworkers, sizeof *heads), **tails = calloc(nworkers, sizeof *tails);
  for (;;) {
    uint64_t v;
    if (read(wq_evfd, &v, 8) < 0 && errno == EINTR) continue;
    job *list = atomic_exchange_explicit(&wq, NULL, memory_order_acquire);
    if (!list) continue;
    job *fifo = NULL;  // the stack is newest first
    while (list) { job *n = list->next; list->next = fifo; fifo = list; list = n; }
    int ok = sqlite3_step(st_begin) == SQLITE_DONE;
    sqlite3_reset(st_begin);
    for (job *j = fifo; j; j = j->next) {
      j->status = 500;
      if (!ok) continue;
      if (j->kind == 1) {
        sqlite3_bind_int64(st_ins, 1, j->uid);
        sqlite3_bind_text(st_ins, 2, j->data + j->nlen, j->blen, SQLITE_STATIC);
        if (sqlite3_step(st_ins) == SQLITE_ROW) {
          j->id = sqlite3_column_int64(st_ins, 0);
          int n = sqlite3_column_bytes(st_ins, 1);
          if (n > (int)sizeof j->created) n = sizeof j->created;
          memcpy(j->created, sqlite3_column_text(st_ins, 1), n);
          j->clen = n;
          j->status = 201;
        }
        sqlite3_reset(st_ins);
      } else {
        sqlite3_bind_int64(st_like, 1, j->uid);
        sqlite3_bind_int64(st_like, 2, j->pid);
        int rc = sqlite3_step(st_like);
        sqlite3_reset(st_like);
        if (rc != SQLITE_DONE) continue;
        if (sqlite3_changes(wdb)) { j->status = 201; continue; }
        sqlite3_bind_int64(st_exists, 1, j->pid);
        rc = sqlite3_step(st_exists);
        sqlite3_reset(st_exists);
        if (rc == SQLITE_ROW) j->status = 200;
        else if (rc == SQLITE_DONE) j->status = 404;
      }
    }
    if (ok) {
      int rc = sqlite3_step(st_commit);
      sqlite3_reset(st_commit);
      if (rc != SQLITE_DONE) {
        sqlite3_exec(wdb, "ROLLBACK", NULL, NULL, NULL);
        for (job *j = fifo; j; j = j->next) j->status = -1;
      }
    }
    // hand the results back, one chain and one wakeup per reader
    for (job *j = fifo, *n; j; j = n) {
      n = j->next;
      int i = j->w->id;
      j->next = NULL;
      if (tails[i]) tails[i]->next = j; else heads[i] = j;
      tails[i] = j;
    }
    for (int i = 0; i < nworkers; i++) {
      if (!heads[i]) continue;
      worker *w = workers[i];
      job *old = atomic_load_explicit(&w->done, memory_order_relaxed);
      do tails[i]->next = old;
      while (!atomic_compare_exchange_weak_explicit(&w->done, &old, heads[i], memory_order_release, memory_order_relaxed));
      heads[i] = tails[i] = NULL;
      if (!old) {
        uint64_t one = 1;
        (void)!write(w->evfd, &one, 8);
      }
    }
    if (atomic_load_explicit(&wal_frames, memory_order_relaxed) >= CKPT_MAIN_FRAMES) {
      atomic_store_explicit(&wal_frames, 0, memory_order_relaxed);
      sqlite3_wal_checkpoint_v2(wdb, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
    }
  }
  return NULL;
}

// ---------------------------------------------------------------------------
// reader threads

static void *worker_main(void *arg) {
  worker *w = arg;
  w->db = db_open("PRAGMA mmap_size=1073741824;PRAGMA cache_size=-8000;PRAGMA temp_store=MEMORY;"
                  "PRAGMA busy_timeout=5000;PRAGMA query_only=1;");
  w->st_feed = prep(w->db, POST_COLS "ORDER BY p.created_at DESC,p.id DESC LIMIT 20");
  w->st_post = prep(w->db, POST_COLS "WHERE p.id=?1");
  w->st_one = prep(w->db, "SELECT 1");

  w->lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  int one = 1;
  setsockopt(w->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  setsockopt(w->lfd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
  if (bind(w->lfd, (struct sockaddr *)&listen_addr, sizeof listen_addr) || listen(w->lfd, 65535)) {
    perror("cannot listen on HOST:PORT");
    exit(1);
  }
  w->epfd = epoll_create1(0);
  struct epoll_event e = {.events = EPOLLIN, .data.fd = w->lfd};
  epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->lfd, &e);
  e.data.fd = w->evfd;
  epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->evfd, &e);

  struct epoll_event *evs = malloc(MAXEV * sizeof *evs);
  for (;;) {
    int n = epoll_wait(w->epfd, evs, MAXEV, -1);
    if (n <= 0) continue;
    w->now = time(NULL);
    for (int i = 0; i < n; i++) {
      // a full batch takes a while under load: take new connections every 128 events too
      if (i && !(i & 127) && !w->accept_off) do_accept(w);
      int fd = evs[i].data.fd;
      uint32_t ev = evs[i].events;
      if (fd == w->lfd) { do_accept(w); continue; }
      if (fd == w->evfd) {
        uint64_t v;
        (void)!read(w->evfd, &v, 8);
        job *j = atomic_exchange_explicit(&w->done, NULL, memory_order_acquire);
        while (j) { job *next = j->next; complete(w, j); j = next; }
        continue;
      }
      conn *c = &conns[fd];
      if (!c->alive || c->dead) continue;
      if ((ev & EPOLLOUT) && c->outlen) {
        on_writable(w, fd, c);
        if (!c->alive || c->dead) continue;
      }
      if (ev & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        if (resumable(c)) conn_read(w, fd, c, (ev & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) != 0);
        else c->pending_in = 1;
      }
    }
  }
  return NULL;
}

static int ncpus(void) {
  cpu_set_t s;
  if (sched_getaffinity(0, sizeof s, &s)) return 1;
  return CPU_COUNT(&s);
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  b64_init();
  start_time = time(NULL);
  const char *secret = getenv("JWT_SECRET");
  if (!secret) secret = "twelve-dollar-challenge";
  hmac_init(secret, strlen(secret));
  db_path = getenv("SQLITE_PATH");
  if (!db_path) { fputs("SQLITE_PATH is not set\n", stderr); return 1; }

  // as many fds as the hard limit allows
  struct rlimit rl;
  getrlimit(RLIMIT_NOFILE, &rl);
  rl.rlim_cur = rl.rlim_max;
  setrlimit(RLIMIT_NOFILE, &rl);
  getrlimit(RLIMIT_NOFILE, &rl);
  maxconn = rl.rlim_cur > (1u << 22) ? (1u << 22) : rl.rlim_cur;
  conns = calloc(maxconn, sizeof *conns);

  listen_addr.sin_family = AF_INET;
  const char *host = getenv("HOST"), *port = getenv("PORT");
  if (!host || inet_pton(AF_INET, host, &listen_addr.sin_addr) != 1) listen_addr.sin_addr.s_addr = 0;
  listen_addr.sin_port = htons(port ? atoi(port) : 3000);

  sqlite3_initialize();
  wdb = db_open("PRAGMA journal_mode=WAL;PRAGMA synchronous=NORMAL;PRAGMA mmap_size=1073741824;"
                "PRAGMA cache_size=-8000;PRAGMA temp_store=MEMORY;PRAGMA busy_timeout=5000;"
                "PRAGMA wal_autocheckpoint=0;PRAGMA journal_size_limit=67108864;");
  sqlite3_wal_hook(wdb, wal_cb, NULL);
  // read the hot indexes once so the first requests hit the OS page cache
  sqlite3_exec(wdb, "SELECT count(*) FROM posts INDEXED BY posts_created_at_id_idx;"
                    "SELECT count(*) FROM likes INDEXED BY likes_post_id_idx;"
                    "SELECT count(*) FROM users;", NULL, NULL, NULL);

  const char *th = getenv("THREADS");
  nworkers = th ? atoi(th) : ncpus();
  if (nworkers < 1) nworkers = 1;
  workers = calloc(nworkers, sizeof *workers);
  for (int i = 0; i < nworkers; i++) {
    workers[i] = calloc(1, sizeof(worker));
    workers[i]->id = i;
    workers[i]->evfd = eventfd(0, EFD_NONBLOCK);
  }
  wq_evfd = eventfd(0, 0);  // blocking: the writer sleeps on it

  pthread_t t;
  pthread_create(&t, NULL, writer_main, NULL);
  pthread_create(&t, NULL, ckpt_main, NULL);
  for (int i = 1; i < nworkers; i++) pthread_create(&t, NULL, worker_main, workers[i]);
  fprintf(stderr, "c single-writer server: %d reader threads\n", nworkers);
  worker_main(workers[0]);
  return 0;
}
