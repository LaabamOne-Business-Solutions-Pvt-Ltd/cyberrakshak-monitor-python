# Changelog

## [1.0.0] - 2026-11-21

First release on PyPI: the Python library served at https://app.cyberrakshak.ai/sdk/python/ since 2026-11-21, as the
module `cyberrakshak_monitor`.

- Reports an exception that ends the program or a thread (the hooks that were there before still run) and, with
  `LoggingHandler`, ERROR log records.
- `init`, `capture_exception`, `capture_message`, `flush`, `scrub`, `close`; options `key`, `endpoint`, `release`,
  `environment`, `enabled`, `sample_rate`, `before_send`, `debug`, `context`, `platform`, `capture_uncaught`.
- Secrets scrubbed before anything leaves, by the rules every Cyber Rakshak library shares. Standard library only.
