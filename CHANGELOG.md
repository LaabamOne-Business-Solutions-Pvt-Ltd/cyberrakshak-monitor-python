# Changelog

## [1.1.0] - 2026-11-22

- Scrubbing, the same rules as every Cyber Rakshak library (the shared `scrub-vectors.json`): IBANs that pass the
  ISO 13616 mod-97 check become `[iban]`; the values after `authorization`, `cookie` / `set-cookie`, `signature`,
  `otp`, `pin`, `cvv`, `cvc`, `iban`, `bban`, `pan`, account number, sort code, card number and bank auth id are
  removed, as whole words only (`company:`, `spinning:` and `japan:` stay).
- `scrub_names` and `scrub_patterns` (init() arguments): names and regular expressions of your own, applied after the built-in
  rules to the message, the stack, the route and context values. They only add: nothing switches the built-in
  rules off. A name or pattern that is not usable is left out (said with `debug`).
- A context entry whose name is a secret name (built in, or one of yours) is sent as `[removed]`.
- The app key's message names where it is made: the site's Security scan tab, Apps, servers and scripts.

## [1.0.0] - 2026-11-21

First release on PyPI: the Python library served at https://app.cyberrakshak.ai/sdk/python/ since 2026-11-21, as the
module `cyberrakshak_monitor`.

- Reports an exception that ends the program or a thread (the hooks that were there before still run) and, with
  `LoggingHandler`, ERROR log records.
- `init`, `capture_exception`, `capture_message`, `flush`, `scrub`, `close`; options `key`, `endpoint`, `release`,
  `environment`, `enabled`, `sample_rate`, `before_send`, `debug`, `context`, `platform`, `capture_uncaught`.
- Secrets scrubbed before anything leaves, by the rules every Cyber Rakshak library shares. Standard library only.
