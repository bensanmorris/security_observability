import threading
import xml.etree.ElementTree as ET
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

import pytest

import k8s_demo_control as control

LAUNCH = 1_000_000.0


class FakeEc2:
    def __init__(self, state="stopped"):
        self.state = state
        self.starts = 0
        self.fail = False

    def describe(self):
        if self.fail:
            raise RuntimeError("boom")
        return self.state, LAUNCH

    def start(self):
        self.starts += 1
        self.state = "pending"


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


def make(tmp_path, state="stopped", limit=4, responses=None, now=LAUNCH + 60):
    clock = Clock(now)
    ec2 = FakeEc2(state)
    responses = responses if responses is not None else {}

    def fetch(url):
        return responses.get(url, (0, ""))

    quota = control.StartQuota(tmp_path / "quota.json", limit, clock)
    controller = control.Controller(ec2, quota, "console", "metrics", "http://public", 60,
                                    clock=clock, fetch=fetch)
    return controller, ec2, clock


def metrics(timestamp):
    return 200, f'cert_analyzer_last_event_timestamp{{node_name="n"}} {timestamp:e}\nother 1\n'


def test_sigv4_matches_aws_documented_example():
    headers = {
        "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        "host": "iam.amazonaws.com",
        "x-amz-date": "20150830T123600Z",
    }
    value = control.sigv4_authorization(
        "GET", "iam.amazonaws.com", "/", "Action=ListUsers&Version=2010-05-08", headers, b"",
        "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "iam",
        "20150830T123600Z")
    assert value == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-date, "
        "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")


def test_parse_describe_reads_state_and_launch_time():
    xml = """<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
      <reservationSet><item><instancesSet><item>
        <instanceState><code>80</code><name>stopped</name></instanceState>
        <launchTime>2026-11-05T11:47:00.000Z</launchTime>
      </item></instancesSet></item></reservationSet></DescribeInstancesResponse>"""
    state, launch = control.parse_describe(ET.fromstring(xml))
    assert state == "stopped"
    assert launch == 1793879220.0


def test_parse_describe_rejects_empty_response():
    with pytest.raises(RuntimeError):
        control.parse_describe(ET.fromstring("<r/>"))


def test_stopped_node_can_be_started(tmp_path):
    controller, _, _ = make(tmp_path)
    status = controller.status()
    assert status["phase"] == "off"
    assert status["can_start"] is True


def test_start_counts_against_the_quota(tmp_path):
    controller, ec2, _ = make(tmp_path)
    code, status = controller.start()
    assert code == 202
    assert ec2.starts == 1
    assert status["phase"] == "starting"
    assert status["starts_used"] == 1


def test_stale_stopped_state_after_a_start_reads_as_starting(tmp_path):
    controller, ec2, clock = make(tmp_path)
    ec2.start = lambda: setattr(ec2, "starts", ec2.starts + 1)  # state stays "stopped"
    code, status = controller.start()
    assert code == 202
    assert status["phase"] == "starting"
    assert status["can_start"] is False
    assert controller.start()[0] == 409
    assert ec2.starts == 1
    assert status["starts_used"] == 1
    clock.now += control.START_SETTLE_SECONDS
    assert controller.status()["phase"] == "off"


def test_start_on_a_non_stopped_node_is_refused_and_not_counted(tmp_path):
    for state in ("pending", "running", "stopping"):
        controller, ec2, _ = make(tmp_path, state=state)
        code, status = controller.start()
        assert code == 409
        assert ec2.starts == 0
        assert status["starts_used"] == 0


def test_daily_cap_refuses_starts_and_resets_next_utc_day(tmp_path):
    controller, ec2, clock = make(tmp_path, limit=1)
    assert controller.start()[0] == 202
    ec2.state = "stopped"
    clock.now += control.START_SETTLE_SECONDS
    code, status = controller.start()
    assert code == 429
    assert ec2.starts == 1
    assert status["can_start"] is False
    clock.now += 86400
    assert controller.start()[0] == 202


def test_quota_survives_a_service_restart(tmp_path):
    controller, ec2, clock = make(tmp_path, limit=1)
    controller.start()
    ec2.state = "stopped"
    restarted = control.StartQuota(tmp_path / "quota.json", 1, clock)
    assert restarted.used() == 1


def test_corrupt_quota_file_fails_closed(tmp_path):
    (tmp_path / "quota.json").write_text("not json")
    controller, ec2, _ = make(tmp_path)
    assert controller.start()[0] == 429
    assert ec2.starts == 0


def test_console_up_without_a_post_boot_event_is_still_starting(tmp_path):
    controller, _, _ = make(tmp_path, "running", responses={
        "console": (200, ""), "metrics": metrics(LAUNCH - 500)})
    assert controller.status()["phase"] == "starting"


def test_post_boot_event_means_ready(tmp_path):
    controller, _, _ = make(tmp_path, "running", responses={
        "console": (200, ""), "metrics": metrics(LAUNCH + 30)})
    status = controller.status()
    assert status["phase"] == "ready"
    assert status["remaining_seconds"] == 3540


def test_console_down_is_starting_even_with_events(tmp_path):
    controller, _, _ = make(tmp_path, "running", responses={"metrics": metrics(LAUNCH + 30)})
    assert controller.status()["phase"] == "starting"


def test_quiet_node_becomes_ready_after_the_grace_period(tmp_path):
    controller, _, _ = make(tmp_path, "running", responses={"console": (200, "")},
                            now=LAUNCH + control.READY_GRACE_SECONDS)
    assert controller.status()["phase"] == "ready"


def test_remaining_never_goes_negative(tmp_path):
    controller, _, _ = make(tmp_path, "running", responses={"console": (200, "")},
                            now=LAUNCH + 7200)
    assert controller.status()["remaining_seconds"] == 0


def test_status_is_cached_between_polls(tmp_path):
    controller, ec2, clock = make(tmp_path)
    controller.status()
    ec2.state = "pending"
    clock.now += 1
    assert controller.status()["phase"] == "off"
    clock.now += control.STATUS_CACHE_SECONDS
    assert controller.status()["phase"] == "starting"


@pytest.fixture
def server(tmp_path):
    controller, ec2, _ = make(tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                control.make_handler(controller, b"// panel"))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1], ec2
    httpd.shutdown()


def request(port, method, path, headers=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, path, headers=headers or {})
    response = connection.getresponse()
    return response.status, response.read()


def test_http_start_requires_the_custom_header(server):
    port, ec2 = server
    assert request(port, "POST", "/k8s-demo/start")[0] == 403
    assert ec2.starts == 0
    assert request(port, "POST", "/k8s-demo/start", {"X-K8s-Demo": "1"})[0] == 202
    assert ec2.starts == 1


def test_http_get_never_starts_the_node(server):
    port, ec2 = server
    assert request(port, "GET", "/k8s-demo/start")[0] == 404
    assert ec2.starts == 0


def test_http_status_and_panel(server):
    port, _ = server
    code, body = request(port, "GET", "/k8s-demo/status")
    assert code == 200 and b'"phase": "off"' in body
    assert request(port, "GET", "/k8s-demo/panel.js") == (200, b"// panel")


def test_http_reports_ec2_failure_without_detail(server):
    port, ec2 = server
    ec2.fail = True
    code, body = request(port, "GET", "/k8s-demo/status")
    assert code == 503
    assert b"boom" not in body
