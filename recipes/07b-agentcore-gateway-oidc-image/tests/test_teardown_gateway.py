import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import teardown_gateway  # noqa: E402


def test_main_deletes_log_group_with_botocore_parameter_name(monkeypatch, capsys):
    calls = {"logs": []}

    class FakeLambda:
        def delete_function(self, **kwargs):
            calls["lambda"] = kwargs

    class FakeIam:
        def delete_role_policy(self, **kwargs):
            calls.setdefault("iam_policies", []).append(kwargs)

        def delete_role(self, **kwargs):
            calls.setdefault("iam_roles", []).append(kwargs)

    class FakeLogs:
        def delete_log_group(self, **kwargs):
            calls["logs"].append(kwargs)

    def fake_client(service):
        return {
            "lambda": FakeLambda(),
            "iam": FakeIam(),
            "logs": FakeLogs(),
        }[service]

    monkeypatch.setattr(
        teardown_gateway,
        "load_state",
        lambda: {"account_id": "123456789012"},
    )
    monkeypatch.setattr(teardown_gateway, "account_id", lambda: "123456789012")
    monkeypatch.setattr(teardown_gateway, "client", fake_client)
    monkeypatch.setattr(teardown_gateway, "verify_absent", lambda state: {"ok": "ok"})

    assert teardown_gateway.main() == 0

    assert calls["logs"] == [
        {"logGroupName": "/aws/lambda/dnsid-oidc-image-target"}
    ]
    assert '"status": "ok"' in capsys.readouterr().out
