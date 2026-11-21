"""Tests for cyberrakshak_monitor, against tests/fake-server.mjs only (127.0.0.1: never a real Cyber Rakshak host).

    python -m unittest discover -s tests -v                        # the module in src/
    CR_TEST_INSTALLED=1 python -m unittest discover -s tests -v    # the one pip installed (from the wheel)

Uses the fake server named by CR_TEST_SERVER, or starts its own with node (Node.js 18 or later on the PATH).
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLED = os.environ.get("CR_TEST_INSTALLED") == "1"
SDK_DIR = None if INSTALLED else os.path.abspath(os.path.join(HERE, "..", "src"))
if SDK_DIR is not None:
    sys.path.insert(0, SDK_DIR)

import cyberrakshak_monitor as m  # noqa: E402

if INSTALLED and "site-packages" not in m.__file__:
    raise RuntimeError("CR_TEST_INSTALLED=1, but cyberrakshak_monitor came from " + m.__file__ + ", not an installed wheel")

KEY = "crk_" + "0" * 32
with open(os.path.join(HERE, "scrub-vectors.json"), encoding="utf-8") as _f:
    VECTORS = json.load(_f)["vectors"]
_server = None
BASE = os.environ.get("CR_TEST_SERVER")


def setUpModule():
    global _server, BASE
    if not BASE:
        _server = subprocess.Popen(["node", os.path.join(HERE, "fake-server.mjs")], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        BASE = json.loads(_server.stdout.readline())["url"]


def tearDownModule():
    m.close()
    if _server is not None:
        _server.stdin.close()
        _server.wait(5)
        _server.stdout.close()


def control(path, body=None):
    data = json.dumps(body).encode() if body is not None else (b"" if path in ("reset",) else None)
    req = urllib.request.Request(BASE + "/__control/" + path, data=data, method="POST" if data is not None else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=30) as r:
        return json.loads(r.read())


def endpoint():
    return BASE + "/api/v1/app-reports"


def requests_(count=0, timeout=5000):
    return control("wait?count=%d&timeout=%d" % (count, timeout)) if count else control("requests")


def problems(reqs):
    return [p for r in reqs for p in r["body"]["errors"]]


class Base(unittest.TestCase):
    def setUp(self):
        m.close()
        control("reset", {})

    def tearDown(self):
        m.close()

    def start(self, **extra):
        options = dict(key=KEY, endpoint=endpoint(), capture_uncaught=False)
        options.update(extra)
        m.init(**options)

    def assertClean(self, reqs):
        for r in reqs:
            self.assertEqual(r["violations"], [], "request %d broke the contract" % r["n"])


class Scrub(Base):
    def test_every_shared_vector(self):
        for v in VECTORS:
            self.assertEqual(m.scrub(v["in"]), v["out"], repr(v["in"]))

    def test_worst_inputs_take_little_time(self):
        mixed = "".join("AbCdEfGh0123456789xyzXYZ+/"[i % 26] for i in range(32000))
        for text in (mixed, "a" * 32000, "token" * 6400, "1" * 32000, "eyJ" * 10000):
            t = time.time()
            m.scrub(text)
            self.assertLess(time.time() - t, 3.0)


class Sending(Base):
    def test_shape_and_scrubbing(self):
        self.start(release="2026.11.21+3", environment="Production", context={"region": "blr1"})
        try:
            raise ValueError("boom for asha@example.com")
        except ValueError as e:
            m.capture_exception(e, route="/orders/42?token=abc", context={"email": "x@example.org", "n": 3, "ok": True, "obj": {"no": 1}})
        self.assertTrue(m.flush(3))
        reqs = requests_()
        self.assertEqual(len(reqs), 1)
        self.assertClean(reqs)
        r = reqs[0]
        self.assertEqual(r["authorization"], "Bearer " + KEY)
        body = r["body"]
        self.assertEqual(body["sdk"], {"name": "cyberrakshak-python", "version": "1.1.0"})
        self.assertEqual(body["platform"], "server")
        self.assertRegex(body["runtime"], r"^python \d+\.\d+$")
        self.assertEqual(body["release"], "2026.11.21+3")
        self.assertEqual(body["environment"], "production")
        p = body["errors"][0]
        self.assertEqual((p["kind"], p["message"], p["route"], p["level"], p["count"]), ("exception", "ValueError: boom for [email]", "/orders/42", "error", 1))
        self.assertIn("test_cyberrakshak_monitor.py", p["stack"])
        self.assertEqual(p["context"], {"region": "blr1", "email": "[email]", "n": 3, "ok": True})

    def test_capture_exception_with_no_argument_takes_the_one_being_handled(self):
        self.start()
        try:
            {}["missing"]
        except KeyError:
            m.capture_exception()
        m.flush(3)
        self.assertEqual(problems(requests_())[0]["message"], "KeyError: 'missing'")

    def test_repeats_are_counted(self):
        self.start()
        for _ in range(5):
            try:
                raise RuntimeError("same problem")
            except RuntimeError as e:
                m.capture_exception(e)
        m.capture_message("a message", level="error")
        m.flush(3)
        reqs = requests_()
        self.assertClean(reqs)
        self.assertEqual(len(reqs), 1)
        a, b = reqs[0]["body"]["errors"]
        self.assertEqual((a["message"], a["count"]), ("RuntimeError: same problem", 5))
        self.assertEqual((b["kind"], b["level"], b["message"]), ("log", "error", "a message"))

    def test_at_most_10_per_request_and_50_waiting(self):
        self.start()
        for i in range(60):
            m.capture_message("distinct %d" % i)
        m.flush(10)
        reqs = requests_()
        self.assertClean(reqs)
        self.assertEqual([len(r["body"]["errors"]) for r in reqs], [10, 10, 10, 10, 10])
        self.assertEqual(problems(reqs)[0]["message"], "distinct 10")

    def test_429_waits_for_retry_after_then_sends_again(self):
        control("plan", {"responses": [{"status": 429, "retryAfter": "1"}]})
        self.start()
        m.capture_message("slow down")
        self.assertFalse(m.flush(3))
        reqs = requests_(2, 6000)
        self.assertEqual(len(reqs), 2)
        self.assertGreaterEqual(reqs[1]["at"] - reqs[0]["at"], 950)
        self.assertEqual(reqs[1]["body"]["errors"][0]["message"], "slow down")

    def test_500_keeps_and_backs_off(self):
        control("plan", {"responses": [{"status": 500}]})
        self.start()
        m.capture_message("server down")
        m.flush(3)
        reqs = requests_(2, 6000)
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[1]["body"]["errors"][0]["message"], "server down")

    def test_422_drops(self):
        control("plan", {"responses": [{"status": 422}]})
        self.start()
        m.capture_message("first")
        m.flush(3)
        m.capture_message("second")
        m.flush(3)
        time.sleep(0.3)
        self.assertEqual([[e["message"] for e in r["body"]["errors"]] for r in requests_()], [["first"], ["second"]])

    def test_401_pauses_sending(self):
        control("plan", {"responses": [{"status": 401}]})
        self.start()
        m.capture_message("first")
        m.flush(3)
        m.capture_message("second")
        m.flush(1)
        time.sleep(0.3)
        self.assertEqual(len(requests_()), 1)

    def test_before_send(self):
        self.start(before_send=lambda p: None)
        m.capture_message("dropped")
        m.flush(1)
        self.start(context={"tenant": "t1"}, before_send=lambda p: dict(p, message="changed", context=None))
        m.capture_message("original")
        m.flush(3)

        def bad(p):
            raise RuntimeError("bad filter")

        self.start(before_send=bad)
        m.capture_message("also dropped")
        m.flush(1)
        reqs = requests_()
        self.assertClean(reqs)
        self.assertEqual(len(reqs), 1)
        p = reqs[0]["body"]["errors"][0]
        self.assertEqual(p["message"], "changed")
        self.assertNotIn("context", p)

    def test_sample_rate_zero_enabled_false_bad_key_send_nothing(self):
        self.start(sample_rate=0)
        for i in range(10):
            m.capture_message("sampled %d" % i)
        m.flush(1)
        self.start(enabled=False)
        m.capture_message("off")
        m.flush(1)
        m.init(key="crw_" + "0" * 32, endpoint=endpoint(), capture_uncaught=False)
        m.capture_message("bad key")
        m.flush(1)
        time.sleep(0.3)
        self.assertEqual(requests_(), [])

    def test_huge_stack_fits_under_64_kb(self):
        self.start()
        for i in range(10):
            m._capture("exception", None, message="huge %d %s" % (i, "é" * 3000), stack=("  File \"/srv/app/x%d.py\", line 1, in f ✓\n" % i) * 8000)
        m.flush(10)
        reqs = requests_()
        self.assertClean(reqs)
        self.assertEqual(len(problems(reqs)), 10)
        for r in reqs:
            self.assertLessEqual(r["bytes"], 65536)

    def test_nothing_makes_it_raise(self):
        class Weird:
            def __str__(self):
                raise RuntimeError("no str")

            __repr__ = __str__

        odd = [None, 0, "", "text", Weird(), {"a": Weird()}, object(), b"\xff\xfe", "\ud800 lone"]
        for x in odd:
            m.capture_exception(x)
            m.capture_message(x)
        self.start()
        for x in odd:
            m.capture_exception(x, route=x, context={"w": Weird(), "s": "\udcff"})
            m.capture_message(x, level=x, route=x, context=x)
        m.flush(3)
        self.assertClean(requests_())


class Hooks(Base):
    def test_thread_exception_reported_and_previous_hook_runs(self):
        seen = []
        previous = threading.excepthook
        threading.excepthook = lambda args: seen.append(str(args.exc_value))
        try:
            m.init(key=KEY, endpoint=endpoint())

            def boom():
                raise RuntimeError("thread-boom")

            t = threading.Thread(target=boom, name="worker-1")
            t.start()
            t.join()
            m.flush(3)
        finally:
            m.close()
            threading.excepthook = previous
        self.assertEqual(seen, ["thread-boom"])
        p = problems(requests_())[0]
        self.assertEqual((p["kind"], p["message"], p["context"]), ("exception", "RuntimeError: thread-boom", {"thread": "worker-1"}))

    def test_logging_handler(self):
        self.start()
        log = logging.getLogger("shop.payments")
        handler = m.LoggingHandler()
        log.addHandler(handler)
        try:
            log.warning("ignored: below ERROR")
            log.error("charge failed for %s", "asha@example.com")
            try:
                1 / 0
            except ZeroDivisionError:
                log.exception("while totting up")
        finally:
            log.removeHandler(handler)
        m.flush(3)
        ps = problems(requests_())
        self.assertEqual([(p["kind"], p["message"]) for p in ps], [("log", "charge failed for [email]"), ("exception", "while totting up\nZeroDivisionError: division by zero")])
        self.assertEqual(ps[0]["context"], {"logger": "shop.payments"})
        self.assertIn("ZeroDivisionError", ps[1]["stack"])


def run_script(source, timeout=20):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("import sys\n" + ("sys.path.insert(0, %r)\n" % SDK_DIR if SDK_DIR is not None else "") + "import cyberrakshak_monitor as monitor\nKEY = %r\nENDPOINT = %r\n" % (KEY, endpoint()))
        f.write(source)
        path = f.name
    try:
        t = time.time()
        p = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, time.time() - t
    finally:
        os.unlink(path)


class Processes(Base):
    def test_uncaught_exception_reported_and_python_prints_it_as_ever(self):
        code, out, err, _ = run_script("monitor.init(key=KEY, endpoint=ENDPOINT)\nraise RuntimeError('crash-boom')\n")
        self.assertEqual(code, 1)
        self.assertIn("Traceback (most recent call last)", err)
        self.assertIn("RuntimeError: crash-boom", err)
        reqs = requests_(1, 3000)
        self.assertClean(reqs)
        self.assertEqual([(p["kind"], p["message"]) for p in problems(reqs)], [("crash", "RuntimeError: crash-boom")])

    def test_the_programs_own_excepthook_still_runs(self):
        code, out, err, _ = run_script(
            "def mine(t, e, tb):\n    print('host hook ran: ' + str(e))\nsys.excepthook = mine\n"
            "monitor.init(key=KEY, endpoint=ENDPOINT)\nraise RuntimeError('hooked-boom')\n"
        )
        self.assertEqual(code, 1)
        self.assertIn("host hook ran: hooked-boom", out)
        self.assertEqual([p["message"] for p in problems(requests_(1, 3000))], ["RuntimeError: hooked-boom"])

    def test_exit_waits_at_most_about_2_s_for_a_slow_console(self):
        control("plan", {"responses": [{"status": 204, "delayMs": 8000}]})
        code, out, err, took = run_script("monitor.init(key=KEY, endpoint=ENDPOINT)\nmonitor.capture_message('slow')\nprint('done')\n")
        self.assertEqual(code, 0)
        self.assertIn("done", out)
        self.assertLess(took, 5.0, "the program took %.1f s to exit" % took)

    def test_a_script_that_ends_by_itself_sends_what_is_waiting(self):
        code, out, err, _ = run_script("monitor.init(key=KEY, endpoint=ENDPOINT, platform='script')\nmonitor.capture_message('import finished with 3 skipped rows')\n")
        self.assertEqual(code, 0)
        reqs = requests_(1, 3000)
        self.assertEqual(reqs[0]["body"]["platform"], "script")
        self.assertEqual([p["message"] for p in problems(reqs)], ["import finished with 3 skipped rows"])

    def test_scrub_names_and_patterns_add_to_the_built_in_rules(self):
        import re as _re
        m.init(key=KEY, endpoint=endpoint(), capture_uncaught=False,
               scrub_names=["x-brand-key", "face.key", "bad name", 7],
               scrub_patterns=[_re.compile(r"faces/[A-Za-z0-9/_.-]+"), "upload-[0-9]+", "(", "x*"],
               context={"client_secret": "abc", "region": "dub1"})
        try:
            raise ValueError("x-brand-key=B1 for faces/2026/a.jpg (upload-77)")
        except ValueError as e:
            m.capture_exception(e, route="/files/face.key=K9",
                                context={"user_pin": 1234, "iban": "IE29AIBK93115212345678", "x-tink-signature": True, "spinning": "yes", "japan": 3})
        self.assertTrue(m.flush(3))
        p = problems(requests_(1))[0]
        self.assertEqual(p["message"], "ValueError: x-brand-key=[removed] for [removed] ([removed])")
        self.assertNotIn("faces/2026", p.get("stack", ""))
        self.assertEqual(p["route"], "/files/face.key=[removed]")
        self.assertEqual(p["context"], {"client_secret": "[removed]", "region": "dub1", "user_pin": "[removed]", "iban": "[removed]",
                                        "x-tink-signature": "[removed]", "spinning": "yes", "japan": 3})
        self.assertEqual(m.scrub("pin=1 x-brand-key=2 password=3"), "pin=[removed] x-brand-key=[removed] password=[removed]")
        m.close()
        self.assertEqual(m.scrub("x-brand-key=2"), "x-brand-key=2")

    def test_scrub_names_and_patterns_limits(self):
        m.init(key=KEY, endpoint=endpoint(), capture_uncaught=False,
               scrub_names=["ok_name"] + ["n%d" % i for i in range(60)],
               scrub_patterns=["fine"] + ["p%dq" % i for i in range(25)])
        self.assertEqual(m.scrub("ok_name=1 n48=2 n49=3 fine p18q p19q"), "ok_name=[removed] n48=[removed] n49=3 [removed] [removed] p19q")
        self.assertEqual(m.scrub("password=1 card 4111 1111 1111 1111"), "password=[removed] card [card]")

    def test_the_key_is_never_printed(self):
        control("plan", {"responses": [{"status": 401}]})
        code, out, err, _ = run_script("monitor.init(key=KEY, endpoint=ENDPOINT, debug=True)\nmonitor.capture_message('x')\nmonitor.flush(2)\n")
        self.assertIn("401", err)
        self.assertNotIn("crk_0", out + err)


if __name__ == "__main__":
    unittest.main()
