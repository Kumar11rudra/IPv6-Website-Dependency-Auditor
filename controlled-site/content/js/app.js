// Fires two API calls: one against a host whose IPv6 path times out at TCP,
// one against a host whose IPv6 path completes TLS but fails at HTTP.
fetch("https://v6-tcp-fail.controlled-test.example/api/data").catch(() => {});
fetch("https://v6-http-fail.controlled-test.example/api/data").catch(() => {});
