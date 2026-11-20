"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}   # request_id -> thời điểm bắt đầu
        self._counter = 0

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Lưu input + thời điểm bắt đầu. Trả về request_id để ghép với output."""
        self._counter += 1
        rid = request_id or f"req-{self._counter:04d}"
        self._open[rid] = time.perf_counter()
        self.logs.append({
            "request_id": rid,
            "user_id": user_id,
            "timestamp": utc_now_iso(),
            "input": text,
            "output": None,
            "blocked": None,
            "layer": None,
            "latency_ms": None,
        })
        return rid

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Ghép output vào entry input tương ứng, tính latency."""
        entry = None
        for e in reversed(self.logs):
            same_req = request_id is not None and e["request_id"] == request_id
            open_of_user = request_id is None and e["user_id"] == user_id and e["output"] is None
            if same_req or open_of_user:
                entry = e
                break
        if entry is None:  # output không có input đi kèm -> vẫn ghi lại
            entry = {"request_id": request_id, "user_id": user_id,
                     "timestamp": utc_now_iso(), "input": None}
            self.logs.append(entry)

        start = self._open.pop(entry["request_id"], None)
        entry.update({
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round((time.perf_counter() - start) * 1000, 1) if start else None,
        })

    def export_json(self, filepath: str | None = None) -> str:
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
