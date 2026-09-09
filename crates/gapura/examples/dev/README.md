# Dev fixture

Run a local backend, then Gapura, then curl.

```bash
python3 -m http.server 9900 &
cargo run -p gapura -- --config-dir crates/gapura/examples/dev --listen-http 127.0.0.1:8080 --listen-https 127.0.0.1:8443 --admin 127.0.0.1:9090
curl -sS -H 'Host: dev.localhost' http://127.0.0.1:8080/ | head -3
curl -sk --resolve dev.localhost:8443:127.0.0.1 https://dev.localhost:8443/ | head -3
curl -s http://127.0.0.1:9090/metrics | grep gapura_requests_total
```

The TLS secret is a throwaway self-signed dev certificate for `dev.localhost`; never reuse it.
