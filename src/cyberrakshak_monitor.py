"""Cyber Rakshak error monitoring for Python, version 1.0.0.

Docs: https://app.cyberrakshak.ai/sdk/README.md
Copyright Laabam One Business Solutions (OPC) Private Limited
Released under the MIT licence: https://app.cyberrakshak.ai/sdk/LICENSE

One file, standard library only, Python 3.9 or later. Sends what goes wrong in your program to your site's Errors
page in the Cyber Rakshak console: the exception's text, its traceback, the route or command, when and how often.
Secrets are scrubbed here before anything leaves (email addresses, tokens and keys, password=... values, query
strings, card numbers); request bodies, headers, cookies, local variables and environment variables are never read.

    import cyberrakshak_monitor as monitor

    monitor.init(key=os.environ["CR_MONITOR_KEY"], release="2026.11.21", environment="production")
    monitor.capture_exception(exc, route="nightly-import", context={"batch": 42})
    monitor.capture_message("Payment provider answered slowly", level="warning")
    logging.getLogger().addHandler(monitor.LoggingHandler())      # every ERROR record, with its traceback if any

Caught by itself: an exception that ends the program (sys.excepthook) and one that ends a thread
(threading.excepthook); the hooks that were there before still run, so tracebacks print as they did. Sending
happens on a background thread; at exit, what is still waiting gets at most 2 s.

Django (settings.py, or an AppConfig.ready()):

    monitor.init(key=os.environ["CR_MONITOR_KEY"], environment="production")
    from django.core.signals import got_request_exception
    got_request_exception.connect(
        lambda sender, request=None, **kw: monitor.capture_exception(
            route=request.resolver_match.route if request is not None and request.resolver_match else None),
        weak=False)

Flask:

    monitor.init(key=os.environ["CR_MONITOR_KEY"], environment="production")
    from flask import got_request_exception, request
    got_request_exception.connect(
        lambda sender, exception, **kw: monitor.capture_exception(
            exception, route=request.url_rule.rule if request.url_rule else None),
        weak=False)

Nothing in here may raise into your code or slow it: a monitor that fails must never become the program's second
problem.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import random
import re
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

__version__ = "1.0.0"
__all__ = ["init", "close", "capture_exception", "capture_message", "flush", "scrub", "LoggingHandler"]

SDK_NAME = "cyberrakshak-python"
DEFAULT_ENDPOINT = "https://app.cyberrakshak.ai/api/v1/app-reports"

_KEY_RE = re.compile(r"^crk_[A-Za-z0-9]{32}$")
_RELEASE_RE = re.compile(r"^[A-Za-z0-9._+\-]{1,60}$")
_ENVIRONMENT_RE = re.compile(r"^[a-z0-9_-]{1,30}$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:?\d{2})$")
_PLATFORMS = ("mobile", "server", "script", "desktop", "other")
_KINDS = ("exception", "crash", "promise", "log", "http", "script")

_MAX_BATCH = 10
_MAX_WAITING = 50
_MAX_MESSAGE = 4000
_MAX_STACK = 16000
_MAX_ROUTE = 200
_MAX_CONTEXT = 20
_MAX_CONTEXT_KEY = 40
_MAX_CONTEXT_VALUE = 300
_MAX_COUNT = 100000
_BODY_LIMIT = 60000
_SEND_AFTER = 2.0
_SEND_TIMEOUT = 5.0
_EXIT_FLUSH = 2.0
_BACKOFF_FIRST = 2.0
_BACKOFF_MAX = 300.0
_RETRY_AFTER_MAX = 86400.0
_BLOCKED = 3600.0


# ── Scrubbing: the same rules, in the same order, in every Cyber Rakshak library ────────────────────────────────────
def _luhn(digits: str) -> bool:
    total = 0
    double = False
    for ch in reversed(digits):
        n = ord(ch) - 48
        if double:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        double = not double
    return total % 10 == 0


_HAS_STRONG = re.compile(r"[0-9A-Z._~+/=]")
_SCRUB_RULES: List[Tuple["re.Pattern[str]", Callable[["re.Match[str]"], str]]] = [
    # A query string: ?name=... up to a space or quote. Where a request went is kept, never what it asked.
    (re.compile(r"""\?[A-Za-z0-9_.%-]+[=&][^ \t\r\n#"'<>]*"""), lambda m: ""),
    # Authorization values.
    (
        re.compile(r"(bearer|basic) +([A-Za-z0-9._~+/=-]{8,})", re.I | re.A),
        lambda m: m.group(1) + " [token]" if _HAS_STRONG.search(m.group(2)) else m.group(0),
    ),
    # password=..., "client_secret": "...", x-api-key: ... (the name is kept, the value is not). The match starts at
    # the word (what comes before it is kept as it is) and allows 40 more name characters after it.
    (
        re.compile(
            r"""((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|session[_-]?id)[A-Za-z0-9_-]{0,40}\\?["']?[ ]*[=:][ ]*\\?["']?)[^ \t\r\n&,;"'<>\\]+""",
            re.I | re.A,
        ),
        lambda m: m.group(1) + "[removed]",
    ),
    # JSON Web Tokens (a header of at most 500 characters).
    (re.compile(r"eyJ[A-Za-z0-9_-]{1,500}\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?"), lambda m: "[token]"),
    # Keys that say what they are.
    (
        re.compile(
            r"(?<![A-Za-z0-9])(?:crk_|crw_|sk_live_|sk_test_|pk_live_|pk_test_|rk_live_|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|xoxb-|xoxp-|xoxa-|AKIA|ASIA|AIza)[A-Za-z0-9_-]{10,}"
        ),
        lambda m: "[token]",
    ),
    # Email addresses.
    (re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), lambda m: "[email]"),
    # Card numbers: 13 to 19 digits (single spaces or dashes between) that pass the Luhn check.
    (
        re.compile(r"(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}"),
        lambda m: "[card]" if _luhn(m.group(0).replace(" ", "").replace("-", "")) else m.group(0),
    ),
    # Long hex runs: session ids, hashes, keys.
    (re.compile(r"[0-9a-fA-F]{32,}"), lambda m: "[token]"),
    # Long random-looking runs: a digit, an upper-case and a lower-case letter in 40 or more of A-Z a-z 0-9 + _ -.
    (
        re.compile(r"[A-Za-z0-9+_-]{40,}"),
        lambda m: "[token]"
        if re.search(r"[0-9]", m.group(0)) and re.search(r"[A-Z]", m.group(0)) and re.search(r"[a-z]", m.group(0))
        else m.group(0),
    ),
]


def scrub(text: Any) -> str:
    """What a text looks like once scrubbed: what this library would send."""
    try:
        out = text if isinstance(text, str) else ("" if text is None else str(text))
        for pattern, replace in _SCRUB_RULES:
            out = pattern.sub(replace, out)
        return out
    except Exception:
        return ""


# ── Helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def _clip(text: Any, limit: int) -> str:
    """At most `limit` characters, and always valid UTF-8 (a lone surrogate becomes U+FFFD)."""
    s = text if isinstance(text, str) else str(text)
    if len(s) > limit:
        s = s[:limit]
    return s.encode("utf-8", "surrogatepass").decode("utf-8", "replace")


def _clean(text: Any, limit: int) -> str:
    return _clip(scrub(_clip(text, limit * 2)), limit)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _describe(exc: Any) -> str:
    try:
        if isinstance(exc, BaseException):
            name = type(exc).__name__
            try:
                text = str(exc)
            except Exception:
                text = ""
            return name + ": " + text if text else name
        if isinstance(exc, str):
            return exc
        return repr(exc)
    except Exception:
        return "Error"


def _stack_of(exc: Any) -> Optional[str]:
    try:
        if isinstance(exc, BaseException):
            return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    except Exception:
        pass
    return None


def _top_frame(stack: Optional[str]) -> str:
    """The frame that raised: in a Python traceback the most recent call is the last 'File ...' line."""
    if not stack:
        return ""
    last = ""
    for line in stack.splitlines():
        if line.startswith("  File "):
            last = line.strip()
    return last


def _clean_context(*sources: Any) -> Optional[Dict[str, Any]]:
    out: Dict[str, Any] = {}
    for source in sources:
        if not isinstance(source, dict):
            continue
        for name in list(source.keys()):
            key = _clip(name, _MAX_CONTEXT_KEY)
            value = source[name]
            if value is None or isinstance(value, bool):
                kept = value
            elif isinstance(value, int):
                kept = value
            elif isinstance(value, float):
                if value != value or value in (float("inf"), float("-inf")):
                    continue
                kept = value
            elif isinstance(value, str):
                kept = _clean(value, _MAX_CONTEXT_VALUE)
            else:
                continue
            if key not in out and len(out) >= _MAX_CONTEXT:
                continue
            out[key] = kept
    return out or None


def _clean_route(route: Any) -> Optional[str]:
    if route is None or route == "":
        return None
    text = _clean(re.split(r"[?#]", str(route))[0], _MAX_ROUTE)
    return text or None


def _normalise(p: Any, fallback_kind: str) -> Optional[Dict[str, Any]]:
    """The shape the console accepts, whatever before_send handed back; None when it is not a problem any more."""
    if not isinstance(p, dict):
        return None
    message = _clip(p.get("message"), _MAX_MESSAGE) if isinstance(p.get("message"), str) else ""
    if not message.strip():
        return None
    count = p.get("count")
    at = p.get("at")
    out: Dict[str, Any] = {
        "kind": p.get("kind") if p.get("kind") in _KINDS else fallback_kind,
        "message": message,
        "level": "warning" if p.get("level") == "warning" else "error",
        "count": min(_MAX_COUNT, max(1, count)) if isinstance(count, int) and not isinstance(count, bool) else 1,
        "at": at if isinstance(at, str) and len(at) <= 40 and _ISO_RE.match(at) else _now_iso(),
    }
    if isinstance(p.get("stack"), str) and p["stack"]:
        out["stack"] = _clip(p["stack"], _MAX_STACK)
    if isinstance(p.get("route"), str) and p["route"]:
        out["route"] = _clip(p["route"], _MAX_ROUTE)
    context = p.get("context")
    if isinstance(context, dict):
        kept: Dict[str, Any] = {}
        for name, value in context.items():
            if len(kept) >= _MAX_CONTEXT:
                break
            if value is None or isinstance(value, (bool, int)) or (isinstance(value, float) and value == value and abs(value) != float("inf")):
                kept[_clip(name, _MAX_CONTEXT_KEY)] = value
            elif isinstance(value, str):
                kept[_clip(name, _MAX_CONTEXT_KEY)] = _clip(value, _MAX_CONTEXT_VALUE)
        if kept:
            out["context"] = kept
    return out


def _retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    text = value.strip()
    if text.isdigit():
        return min(_RETRY_AFTER_MAX, float(text))
    try:
        when = parsedate_to_datetime(text)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return min(_RETRY_AFTER_MAX, max(0.0, (when - datetime.now(timezone.utc)).total_seconds()))
    except Exception:
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib's signature
        return None


_opener = urllib.request.build_opener(_NoRedirect())
_local = threading.local()


# ── State ────────────────────────────────────────────────────────────────────────────────────────────────────────────
class _State:
    def __init__(self) -> None:
        self.key = ""
        self.endpoint = DEFAULT_ENDPOINT
        self.release: Optional[str] = None
        self.environment: Optional[str] = None
        self.sample_rate = 1.0
        self.before_send: Optional[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = None
        self.debug = False
        self.context: Optional[Dict[str, Any]] = None
        self.platform = "server"
        self.runtime = "python"
        self.queue: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.lock = threading.Lock()
        self.wake = threading.Condition(self.lock)
        self.send_lock = threading.Lock()
        self.due = 0.0
        self.not_before = 0.0
        self.backoff = 0.0
        self.blocked_until = 0.0
        self.logged: set = set()
        self.closed = False
        self.thread: Optional[threading.Thread] = None
        self.pid = os.getpid()
        self.previous_excepthook: Any = None
        self.previous_threading_hook: Any = None


_state: Optional[_State] = None


def _debug(state: Optional[_State], message: str) -> None:
    try:
        if state is not None and state.debug:
            sys.stderr.write("[cyberrakshak-monitor] " + message + "\n")
    except Exception:
        pass


def _debug_once(state: _State, key: Any, message: str) -> None:
    if key not in state.logged:
        state.logged.add(key)
        _debug(state, message)


def _fingerprint(p: Dict[str, Any]) -> str:
    return p["kind"] + "\n" + p["message"] + "\n" + _top_frame(p.get("stack"))


def _merge_front(state: _State, entries: List[Tuple[str, Dict[str, Any]]]) -> None:
    """Puts problems back in front of the queue (to be tried again), counting any that came in since. Lock held."""
    if not entries:
        return
    merged: "OrderedDict[str, Dict[str, Any]]" = OrderedDict(entries)
    for fid, p in state.queue.items():
        have = merged.get(fid)
        if have is not None:
            have["count"] = min(_MAX_COUNT, have["count"] + p["count"])
            have["at"] = p["at"]
        else:
            merged[fid] = p
    while len(merged) > _MAX_WAITING:
        merged.popitem(last=False)
    state.queue = merged


def _capture(kind: str, exc: Any, message: Any = None, stack: Any = None, route: Any = None, context: Any = None, level: Any = None) -> None:
    state = _state
    if state is None or state.closed or getattr(_local, "busy", False):
        return
    _local.busy = True
    try:
        if isinstance(exc, BaseException):
            if getattr(exc, "__cyberrakshak_reported__", False):
                return
            try:
                exc.__cyberrakshak_reported__ = True  # type: ignore[attr-defined]
            except Exception:
                pass
        now = time.time()
        if now < state.blocked_until:
            return
        if state.sample_rate < 1 and not random.random() < state.sample_rate:
            return
        if stack is None:
            stack = _stack_of(exc)
        draft: Dict[str, Any] = {
            "kind": kind,
            "message": _clean(message if message is not None else _describe(exc), _MAX_MESSAGE) or "(no message)",
            "level": level if level in ("error", "warning") else ("warning" if kind == "log" else "error"),
            "count": 1,
            "at": _now_iso(),
        }
        if isinstance(stack, str) and stack:
            draft["stack"] = _clean(stack, _MAX_STACK)
        clean_route = _clean_route(route)
        if clean_route:
            draft["route"] = clean_route
        clean_context = _clean_context(state.context, context)
        if clean_context:
            draft["context"] = clean_context
        if state.before_send is not None:
            try:
                changed = state.before_send(draft)
            except Exception as e:
                _debug(state, "before_send raised, so the problem was not sent: " + _describe(e))
                return
            problem = _normalise(changed, kind)
        else:
            problem = _normalise(draft, kind)
        if problem is None:
            return
        fid = _fingerprint(problem)
        with state.wake:
            have = state.queue.get(fid)
            if have is not None:
                have["count"] = min(_MAX_COUNT, have["count"] + problem["count"])
                have["at"] = problem["at"]
            else:
                if not state.queue:
                    state.due = now + _SEND_AFTER
                state.queue[fid] = problem
                while len(state.queue) > _MAX_WAITING:
                    state.queue.popitem(last=False)
            state.wake.notify()
        _ensure_thread(state)
    except Exception as e:
        _debug(state, "could not capture: " + _describe(e))
    finally:
        _local.busy = False


def _envelope(state: _State, problems: List[Dict[str, Any]]) -> Dict[str, Any]:
    body: Dict[str, Any] = {"sdk": {"name": SDK_NAME, "version": __version__}, "platform": state.platform, "runtime": state.runtime}
    if state.release:
        body["release"] = state.release
    if state.environment:
        body["environment"] = state.environment
    body["errors"] = problems
    return body


def _dump(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _fit(state: _State, entries: List[Tuple[str, Dict[str, Any]]]):
    """The JSON for a batch, cut to fit under 64 KB: long stacks are halved first, then fewer problems go in one request."""
    rest: List[Tuple[str, Dict[str, Any]]] = []
    body = b""
    for _ in range(200):
        body = _dump(_envelope(state, [p for _, p in entries]))
        if len(body) <= _BODY_LIMIT:
            return body, entries, rest
        longest = None
        for e in entries:
            s = e[1].get("stack")
            if s and len(s) > 1000 and (longest is None or len(s) > len(longest[1]["stack"])):
                longest = e
        if longest is not None:
            longest[1]["stack"] = _clip(longest[1]["stack"], len(longest[1]["stack"]) // 2) + "\n[cut]"
            continue
        if len(entries) > 1:
            rest.insert(0, entries.pop())
            continue
        p = entries[0][1]
        if len(p["message"]) > 1000:
            p["message"] = _clip(p["message"], len(p["message"]) // 2)
        elif "context" in p:
            del p["context"]
        elif "stack" in p:
            del p["stack"]
        else:
            break
    return body, entries, rest


def _post(state: _State, body: bytes, timeout: float) -> Tuple[int, Optional[float]]:
    request = urllib.request.Request(
        state.endpoint,
        data=body,
        method="POST",
        headers={"Authorization": "Bearer " + state.key, "Content-Type": "application/json", "User-Agent": SDK_NAME + "/" + __version__},
    )
    try:
        with _opener.open(request, timeout=max(0.1, timeout)) as response:
            response.read()
            return response.status, _retry_after(response.headers.get("Retry-After"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, _retry_after(e.headers.get("Retry-After") if e.headers is not None else None)
        finally:
            try:
                e.read()
                e.close()
            except Exception:
                pass
    except Exception as e:
        _debug(state, "could not reach " + state.endpoint + ": " + _describe(e))
        return 0, None


def _send_batch(state: _State, timeout: float) -> str:
    """One request with up to 10 waiting problems: 'sent', 'empty', 'later' (kept for a retry) or 'dropped'."""
    with state.wake:
        if not state.queue:
            return "empty"
        now = time.time()
        if now < state.blocked_until:
            state.queue.clear()
            return "dropped"
        if now < state.not_before:
            return "later"
        taken = []
        while state.queue and len(taken) < _MAX_BATCH:
            taken.append(state.queue.popitem(last=False))
    # Taken out of the queue, these are this thread's alone: cut to size without holding the lock.
    body, entries, rest = _fit(state, taken)
    with state.wake:
        _merge_front(state, rest)
    status, retry_after = _post(state, body, timeout)
    with state.wake:
        if state.queue:
            state.due = time.time() + _SEND_AFTER
        if 200 <= status < 300:
            state.backoff = 0.0
            return "sent"
        if status == 0 or status == 429 or status >= 500:
            _merge_front(state, entries)
            wait = retry_after
            if wait is None:
                state.backoff = min(_BACKOFF_MAX, state.backoff * 2) if state.backoff else _BACKOFF_FIRST
                wait = state.backoff
            state.not_before = time.time() + wait
            _debug(state, "the console answered %s; trying again in %d s" % (status or "nothing", round(wait)))
            return "later"
        if status in (401, 403):
            state.blocked_until = time.time() + _BLOCKED
            state.queue.clear()
            _debug_once(state, status, "the console answered %d (%s): nothing is sent for an hour" % (status, "the key is not known" if status == 401 else "the site is not verified or its monitoring is off"))
            return "dropped"
        _debug_once(state, status, "the console answered %d: those problems were dropped" % status)
        return "dropped"


def _worker(state: _State) -> None:
    _local.busy = True  # whatever this thread does is the library's own: never captured
    while True:
        try:
            with state.wake:
                while not state.closed:
                    if state.queue:
                        wait = max(state.due, state.not_before) - time.time()
                        if wait <= 0:
                            break
                        state.wake.wait(min(wait, 60.0))
                    else:
                        state.wake.wait(60.0)
                if state.closed:
                    return
            if state.send_lock.acquire(timeout=1.0):
                try:
                    _send_batch(state, _SEND_TIMEOUT)
                finally:
                    state.send_lock.release()
        except Exception as e:
            _debug(state, "sender: " + _describe(e))
            time.sleep(1.0)


def _ensure_thread(state: _State) -> None:
    if state.pid != os.getpid():
        _after_fork_reset(state)
    if state.thread is None or not state.thread.is_alive():
        thread = threading.Thread(target=_worker, args=(state,), name="cyberrakshak-monitor", daemon=True)
        state.thread = thread
        thread.start()


def _after_fork_reset(state: _State) -> None:
    """In a child process the parent's sender thread does not exist: start afresh (the parent sends its own problems)."""
    state.pid = os.getpid()
    state.lock = threading.Lock()
    state.wake = threading.Condition(state.lock)
    state.send_lock = threading.Lock()
    state.queue = OrderedDict()
    state.thread = None


def flush(timeout: float = _EXIT_FLUSH) -> bool:
    """Sends what is waiting now, from this thread, for at most `timeout` seconds. True when nothing is left waiting."""
    state = _state
    if state is None:
        return True
    try:
        if state.pid != os.getpid():
            _after_fork_reset(state)
        deadline = time.time() + max(0.0, float(timeout))
        while time.time() < deadline:
            with state.wake:
                if not state.queue or time.time() < state.not_before:
                    break
            if not state.send_lock.acquire(timeout=max(0.0, deadline - time.time())):
                break
            try:
                result = _send_batch(state, min(_SEND_TIMEOUT, max(0.1, deadline - time.time())))
            finally:
                state.send_lock.release()
            if result != "sent":
                break
        with state.wake:
            return not state.queue
    except Exception as e:
        _debug(state, "flush: " + _describe(e))
        return False


# ── Hooks ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _excepthook(exc_type, exc, tb):  # type: ignore[no-untyped-def]
    state = _state
    previous = state.previous_excepthook if state is not None else None
    try:
        if exc is not None and not isinstance(exc, KeyboardInterrupt):
            if exc.__traceback__ is None and tb is not None:
                exc = exc.with_traceback(tb)
            _capture("crash", exc)
    except Exception:
        pass
    (previous or sys.__excepthook__)(exc_type, exc, tb)


def _threading_excepthook(args):  # type: ignore[no-untyped-def]
    state = _state
    previous = state.previous_threading_hook if state is not None else None
    try:
        if args.exc_value is not None and not isinstance(args.exc_value, SystemExit):
            name = getattr(args.thread, "name", None)
            _capture("exception", args.exc_value, context={"thread": name} if name else None)
    except Exception:
        pass
    (previous or threading.__excepthook__)(args)


def _at_exit() -> None:
    state = _state
    if state is not None and not state.closed:
        flush(_EXIT_FLUSH)


class LoggingHandler(logging.Handler):
    """A logging handler that reports ERROR records (or the level you give): their message, and their traceback when
    logged with exc_info (logger.exception). The logger's name goes in the context; extra={"route": ...} sets the route."""

    def __init__(self, level: int = logging.ERROR) -> None:
        super().__init__(level)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if getattr(_local, "busy", False) or record.name.startswith("cyberrakshak_monitor"):
                return
            exc = record.exc_info[1] if record.exc_info and record.exc_info[1] is not None else None
            try:
                text = record.getMessage()
            except Exception:
                text = str(record.msg)
            if exc is not None:
                # Already reported (capture_exception, or Django's own record of a request's exception)? Then once.
                if getattr(exc, "__cyberrakshak_reported__", False):
                    return
                text = text + "\n" + _describe(exc) if text else _describe(exc)
            _capture(
                "exception" if exc is not None else "log",
                exc,
                message=text,
                route=getattr(record, "route", None),
                context={"logger": record.name},
                level="warning" if record.levelno < logging.ERROR else "error",
            )
        except Exception:
            pass


# ── API ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def init(
    key: Optional[str] = None,
    endpoint: Optional[str] = None,
    release: Optional[str] = None,
    environment: Optional[str] = None,
    enabled: bool = True,
    sample_rate: float = 1.0,
    before_send: Optional[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = None,
    debug: bool = False,
    context: Optional[Dict[str, Any]] = None,
    platform: str = "server",
    capture_uncaught: bool = True,
) -> None:
    """Starts monitoring. key is the crk_ key from your site's Errors page; platform is 'server' unless you say
    'script', 'desktop' or 'other'; before_send(problem) may change a problem or return None to drop it."""
    global _state
    try:
        close()
        probe = _State()
        probe.debug = bool(debug)
        if not enabled:
            return
        if not isinstance(key, str) or not _KEY_RE.match(key.strip()):
            _debug(probe, "not started: key must be the crk_ key from your site's Errors page")
            return
        state = probe
        state.key = key.strip()
        state.endpoint = endpoint if isinstance(endpoint, str) and re.match(r"^https?://\S+$", endpoint, re.I) else DEFAULT_ENDPOINT
        if release is not None:
            release = str(release)
            if not _RELEASE_RE.match(release):
                _debug(state, "release left out: it may hold only A-Z a-z 0-9 . _ + - (at most 60)")
                release = None
        state.release = release
        if environment is not None:
            environment = str(environment).lower()
            if not _ENVIRONMENT_RE.match(environment):
                _debug(state, "environment left out: it may hold only a-z 0-9 _ - (at most 30)")
                environment = None
        state.environment = environment
        try:
            state.sample_rate = min(1.0, max(0.0, float(sample_rate)))
        except Exception:
            state.sample_rate = 1.0
        state.before_send = before_send if callable(before_send) else None
        state.context = context if isinstance(context, dict) else None
        state.platform = platform if platform in _PLATFORMS else "server"
        state.runtime = "python %d.%d" % (sys.version_info[0], sys.version_info[1])
        _state = state
        if capture_uncaught:
            state.previous_excepthook = sys.excepthook
            sys.excepthook = _excepthook
            state.previous_threading_hook = threading.excepthook
            threading.excepthook = _threading_excepthook
        _debug(state, "started: %s %s reporting to %s" % (SDK_NAME, __version__, state.endpoint))
    except Exception as e:
        _state = None
        try:
            if debug:
                sys.stderr.write("[cyberrakshak-monitor] not started: " + _describe(e) + "\n")
        except Exception:
            pass


def close() -> None:
    """Stops monitoring: the hooks go back to what they were and anything still waiting is forgotten (flush() first)."""
    global _state
    state = _state
    _state = None
    if state is None:
        return
    try:
        state.closed = True
        with state.wake:
            state.wake.notify_all()
        if sys.excepthook is _excepthook and state.previous_excepthook is not None:
            sys.excepthook = state.previous_excepthook
        if threading.excepthook is _threading_excepthook and state.previous_threading_hook is not None:
            threading.excepthook = state.previous_threading_hook
    except Exception:
        pass


def capture_exception(exc: Optional[BaseException] = None, route: Optional[str] = None, context: Optional[Dict[str, Any]] = None, level: str = "error") -> None:
    """Reports an exception you caught (with no argument: the one being handled now)."""
    try:
        if exc is None:
            exc = sys.exc_info()[1]
        if exc is None:
            return
        _capture("exception", exc, route=route, context=context, level=level)
    except Exception:
        pass


def capture_message(text: Any, level: str = "warning", route: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> None:
    """Reports a message; level 'warning' (the default) or 'error'."""
    try:
        _capture("log", None, message=text if isinstance(text, str) else _describe(text), route=route, context=context, level=level)
    except Exception:
        pass


atexit.register(_at_exit)
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=lambda: _state is not None and _after_fork_reset(_state))
