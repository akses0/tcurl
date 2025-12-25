# tcurl

A custom curl implementation built on my socket library with help from Grok.

Zero dependencies except OpenSSL for crypto primitives. Everything else is hand-rolled.

```
10.0.0.167.48458 > 54.158.135.159.443: Flags [S]
  54.158.135.159.443 > 10.0.0.167.48458: Flags [S.], ack
```

DNS resolution → TCP handshake → TLS negotiation → HTTP request → encrypted response.

All custom. No libcurl. No libuv.

---

## What's in the box

- Full TLS 1.3 handshake + certificate chain validation
- HTTP/1.1 & HTTP/2 with HPACK compression
- Complete DNS resolver with DoT, DoH, DNSSEC
- io_uring async backend with SQPOLL + registered buffers
- WebSocket + WebSocket-over-HTTP/2
- SOCKS4/5 + HTTP CONNECT proxy support
- Connection pooling with health monitoring + rate limiting
- Happy Eyeballs v2 dual-stack connection racing
- Arena-based memory management
- Custom exception handling (TRY/EXCEPT/FINALLY)

## Build

```bash
mkdir build && cd build
cmake .. -DENABLE_HTTP_COMPRESSION=ON -DENABLE_TLS=ON
make -j$(nproc)
```

## What's redacted

- HTTP/3 + QUIC (in progress)
- Simple API layer
- Fuzz harnesses
- Unit/integration test suite
- Examples folder (30+ demo programs)

## About the API

The Simple API from previous demos encapsulated much of the underlying functionality—exception handling, connection management, etc. This demo uses the lower layer of the socket library directly. The Simple API isn't public yet because I haven't had time to fully fuzz it.

The exception-based API shown here has been fuzzed (not full coverage) and hammered with ASan/UBSan. It passes the full test suite. There are still some issues.

Still under active development. The code shown is battle-tested, not final.
