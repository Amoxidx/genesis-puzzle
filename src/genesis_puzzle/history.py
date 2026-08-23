from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Mapping, Optional, Protocol, Sequence
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from genesis_puzzle.config import HistoryConfig


@dataclass(frozen=True)
class HistoryResult:
    address: str
    seen_on_chain: bool
    balance_sats: int
    total_received_sats: int
    total_sent_sats: int
    transaction_count: int
    status: str
    first_seen: Optional[str]


class AddressHistoryProvider(Protocol):
    def fetch_batch(self, addresses: Sequence[str]) -> Mapping[str, HistoryResult]: ...


class NullHistoryProvider:
    def fetch_batch(self, addresses: Sequence[str]) -> Mapping[str, HistoryResult]:
        raise RuntimeError("network history is disabled unless --yes-network is set")


class BlockchainInfoMultiaddrProvider:
    """One HTTP request per address batch via blockchain.info's multiaddr API."""

    def __init__(self, config: HistoryConfig) -> None:
        self.config = config

    @staticmethod
    def _status(transaction_count: int, balance: int, total_sent: int) -> str:
        if transaction_count == 0:
            return "never_seen"
        if balance > 0:
            return "currently_funded"
        if total_sent > 0:
            return "spent_history"
        return "seen_but_empty"

    def fetch_batch(self, addresses: Sequence[str]) -> Mapping[str, HistoryResult]:
        requested = list(dict.fromkeys(addresses))
        if not requested:
            return {}
        query = urlencode({"active": "|".join(requested), "n": "1"})
        url = self.config.base_url.rstrip("/") + "/multiaddr?" + query
        request = Request(url, headers={"User-Agent": "genesis-puzzle-local-research/0.1"})
        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("batched history lookup failed for public addresses") from exc

        rows = payload.get("addresses")
        if not isinstance(rows, list):
            raise RuntimeError("batched history response has no address list")
        out = {}
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("batched history response contains an invalid address row")
            address = str(row.get("address", ""))
            if address not in requested or address in out:
                raise RuntimeError("batched history response contains an unexpected address")
            tx_count = int(row.get("n_tx", 0))
            balance = int(row.get("final_balance", 0))
            total_received = int(row.get("total_received", 0))
            total_sent = int(row.get("total_sent", 0))
            out[address] = HistoryResult(
                address=address,
                seen_on_chain=tx_count > 0,
                balance_sats=balance,
                total_received_sats=total_received,
                total_sent_sats=total_sent,
                transaction_count=tx_count,
                status=self._status(tx_count, balance, total_sent),
                first_seen=None,
            )
        missing = set(requested) - set(out)
        if missing:
            raise RuntimeError(
                f"batched history response omitted {len(missing)} requested address(es)"
            )
        return out


def chunked(items: Sequence[str], size: int) -> List[Sequence[str]]:
    if size < 1:
        raise ValueError("batch size must be >= 1")
    return [items[i : i + size] for i in range(0, len(items), size)]
