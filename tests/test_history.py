from __future__ import annotations

import io
import json
from urllib.parse import parse_qs, urlparse

import pytest

import genesis_puzzle.history as history_module
from genesis_puzzle.config import HistoryConfig
from genesis_puzzle.history import BlockchainInfoMultiaddrProvider


class _Response:
    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return io.BytesIO(self._body).read()


def _config() -> HistoryConfig:
    return HistoryConfig(
        batch_size=40,
        provider="blockchain.info-multiaddr",
        base_url="https://blockchain.info",
        timeout_seconds=20,
    )


def test_multiaddr_provider_uses_one_http_request_for_whole_batch(monkeypatch):
    addresses = ["1ExampleOne", "bc1qexampletwo"]
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        return _Response(
            {
                "addresses": [
                    {
                        "address": addresses[0],
                        "n_tx": 0,
                        "final_balance": 0,
                        "total_received": 0,
                        "total_sent": 0,
                    },
                    {
                        "address": addresses[1],
                        "n_tx": 2,
                        "final_balance": 0,
                        "total_received": 100,
                        "total_sent": 100,
                    },
                ]
            }
        )

    monkeypatch.setattr(history_module, "urlopen", fake_urlopen)
    results = BlockchainInfoMultiaddrProvider(_config()).fetch_batch(addresses)

    assert len(calls) == 1
    query = parse_qs(urlparse(calls[0][0]).query)
    assert query["active"] == ["|".join(addresses)]
    assert results[addresses[0]].status == "never_seen"
    assert results[addresses[1]].status == "spent_history"
    assert results[addresses[1]].transaction_count == 2


def test_multiaddr_provider_rejects_omitted_address(monkeypatch):
    monkeypatch.setattr(
        history_module,
        "urlopen",
        lambda *_args, **_kwargs: _Response({"addresses": []}),
    )
    with pytest.raises(RuntimeError, match="omitted"):
        BlockchainInfoMultiaddrProvider(_config()).fetch_batch(["1Missing"])
