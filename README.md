# cyberrakshak-monitor

Cyber Rakshak error monitoring for **Python 3.9+**: what goes wrong in your program lands on your site's **Errors**
page in the Cyber Rakshak console, scrubbed of secrets before it leaves. One module, standard library only, no
dependencies.

## What it catches

- **An exception that ends the program** (`sys.excepthook`) and **one that ends a thread** (`threading.excepthook`).
  The hooks that were there before still run, so tracebacks print as they did.
- **ERROR log records**, with `LoggingHandler` (with their traceback, if any).
- Anything you report yourself: `capture_exception()` and `capture_message()`. Django and Flask need two lines each
  (below).

Sending happens on a background thread; at exit, what is still waiting gets at most 2 s.

## Install

```sh
pip install cyberrakshak-monitor
```

## Use

```python
import logging, os
import cyberrakshak_monitor as monitor
monitor.init(key=os.environ["CR_MONITOR_KEY"], release="2026.11.21", environment="production")
logging.getLogger().addHandler(monitor.LoggingHandler())     # every ERROR record
monitor.capture_exception(exc, route="nightly-import", context={"batch": 42})
```

The key is your site's app key (`crk_…`), made on the site's **Security scan** tab: under **Apps, servers and scripts**, press **Make an app key**.

Django (settings.py, or an `AppConfig.ready()`):

```python
from django.core.signals import got_request_exception
got_request_exception.connect(lambda sender, request=None, **kw: monitor.capture_exception(
    route=request.resolver_match.route if request is not None and request.resolver_match else None), weak=False)
```

Flask:

```python
from flask import got_request_exception, request
got_request_exception.connect(lambda sender, exception, **kw: monitor.capture_exception(
    exception, route=request.url_rule.rule if request.url_rule else None), weak=False)
```

## Options (`init(...)`)

| Option | Meaning |
|---|---|
| `key` | Your site's app key, `crk_` and 32 letters or digits. Required; with no valid key the library does nothing. |
| `endpoint` | Where reports go. Default `https://app.cyberrakshak.ai/api/v1/app-reports`. |
| `release` | Your version or build (`A-Z a-z 0-9 . _ + -`, at most 60), so a problem shows the release it started in. |
| `environment` | `production`, `staging`… (`a-z 0-9 _ -`, at most 30). |
| `enabled` | `False` sends nothing (default `True`). |
| `sample_rate` | 0 to 1: the share of problems sent (default 1, all). |
| `before_send` | Gets each problem (a dict), already scrubbed; return it (changed if you like) or `None` to drop it. |
| `debug` | Says on standard error what the library does and why something was not sent. The key is never printed. |
| `context` | Values sent with every problem: at most 20, strings (300 characters), numbers, True/False. |
| `scrub_names` | Names of your own whose values are removed, like `password=`: whole words, `A-Z a-z 0-9 _ . -`, at most 50. Only adds to the built-in rules. |
| `scrub_patterns` | Regular expressions of your own (compiled, or strings): what they match becomes `[removed]`. At most 20; one that does not compile, or matches an empty text, is left out. Only adds to the built-in rules. |
| `platform` | `server` (the default), `script`, `desktop`, `mobile` or `other`. |
| `capture_uncaught` | Report exceptions that end the program or a thread (default `True`). |

Functions: `init(...)`, `capture_exception(exc=None, route=None, context=None, level="error")` (no argument: the
exception being handled now), `capture_message(text, level="warning", route=None, context=None)`, `flush(timeout=2)`
(`True` when nothing is left waiting), `scrub(text)` (shows what a text would become), `close()`, and
`LoggingHandler(level=logging.ERROR)`.

## What is sent, and what never is

Sent, per problem: its kind (exception, crash, log message), its message, its traceback (file, line and function;
never local variables or argument values), the route or command (never its query string), the level, how many times it
happened and when last; with each request: the library's name and version, `python` and its version, your release and
environment.

Never sent: request or response bodies, headers, cookies, sessions, form fields, environment variables, local
variables.

**Scrubbed before anything leaves**: query strings; `Bearer`/`Basic` values; the value after `password`, `secret`,
`token`, `api_key` and the like; JSON Web Tokens; keys that say what they are (`crk_`, `sk_live_`, `ghp_`, `AKIA`…);
email addresses; IBANs (mod-97 checked); card numbers (Luhn-checked); the value after `pin`, `otp`, `cvv`, `iban`,
`sort_code`, `card_number`, `account_number`, `cookie`, `signature`, `authorization` and the like, as whole words only
(`company:` and `spinning:` stay); long hex and random-looking runs. They become `[removed]`, `[token]`, `[email]`,
`[iban]` or `[card]`, and a context entry whose name is one of these names is sent as `[removed]`. `scrub_names` and
`scrub_patterns` add names and patterns of your own; nothing switches the built-in rules off. The console scrubs
everything again when it arrives.

At most 10 problems go per request, each request under 64 KB; repeats of one problem are counted, not resent; a request
takes at most 5 s; `429` and `5xx` answers are retried later (never before `Retry-After`). Nothing in the library
raises into your code. After `os.fork()` the child starts its own sending thread.

Full documentation, the same library for other platforms, and every file's SHA-256:
**https://app.cyberrakshak.ai/sdk/README.md**

## Development

```sh
python -m unittest discover -s tests -v          # the module in src/, against tests/fake-server.mjs (needs Node.js 18+)
python -m build                                  # dist/: the wheel and the sdist
CR_TEST_INSTALLED=1 python -m unittest discover -s tests -v   # the same tests on the installed wheel
```

The fake server listens on 127.0.0.1 only: no test talks to a real Cyber Rakshak host. `src/cyberrakshak_monitor.py`,
`LICENSE` and the two test fixtures are byte for byte the ones served at https://app.cyberrakshak.ai/sdk/ and are not
edited here: they are changed in the Cyber Rakshak console's repository and copied by its `scripts/sdk-packages.mjs`
(whose `--check` also checks that `version` in pyproject.toml is the library's).

## For maintainers

Publishing is by tag, through PyPI's **trusted publishing** (`.github/workflows/publish.yml`, `pypa/gh-action-pypi-publish`
with `id-token: write` in the environment `pypi`): no PyPI token is stored anywhere. A release: copy the new module in,
set `version` in pyproject.toml, add the CHANGELOG entry, commit, tag `vX.Y.Z`, push the tag.

Before the first tag, the PyPI account that will own the project adds a **pending publisher** (pypi.org → Your account →
Publishing → Add a new pending publisher → GitHub): PyPI project name `cyberrakshak-monitor`, owner
`LaabamOne-Business-Solutions-Pvt-Ltd`, repository name `cyberrakshak-monitor-python`, workflow name `publish.yml`,
environment name `pypi`. The first publish then creates the project. In this repository's GitHub settings, the
environment `pypi` can require a reviewer's approval before each publish.

## Licence

MIT. Copyright (c) 2026 Laabam One Business Solutions (OPC) Private Limited. See [LICENSE](LICENSE).
