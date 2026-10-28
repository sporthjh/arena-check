# -*- coding: utf-8 -*-
"""해시 체인 유틸(2026-10-27). 기록 하나(record)마다 이전 해시를 이어 붙여, 중간 기록이
빠지거나 바뀌면 이어지는 해시가 안 맞아 드러나게 한다. 끊김을 만나면 막지 않고 표시만 하고 이어 간다."""
import hashlib
import json

GENESIS = "GENESIS"


def record_hash(prev_hash: str, record: dict) -> str:
    """record(해시·prev_hash 필드는 뺀 것)를 정렬된 JSON으로 굳혀 이전 해시와 함께 해시"""
    canon = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + "|" + canon).encode("utf-8")).hexdigest()


def append_entry(state: dict, record: dict, kind: str = "turn") -> dict:
    """state={'last_hash':...,'last_uuid':...} 를 보고 새 저장 줄(entry)을 만들어 돌려줌.
    state는 호출부에서 갱신해 파일에 저장해야 함(이 함수는 안 건드림)."""
    prev_hash = state.get("last_hash") or GENESIS
    h = record_hash(prev_hash, record)
    entry = {"kind": kind, "prev_hash": prev_hash, "hash": h, **record}
    return entry


def break_entry(state: dict, reason: str, ts: str) -> dict:
    prev_hash = state.get("last_hash") or GENESIS
    record = {"reason": reason, "ts": ts}
    h = record_hash(prev_hash, {"BREAK": True, **record})
    return {"kind": "break", "prev_hash": prev_hash, "hash": h, **record}


def verify_chain(entries: list) -> list:
    """끊긴 자리의 인덱스 목록을 돌려줌(비어 있으면 전부 이어짐)"""
    broken = []
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("prev_hash") != prev:
            broken.append(i)
        rec = {k: v for k, v in e.items() if k not in ("kind", "prev_hash", "hash")}
        if e.get("kind") == "break":
            expect = record_hash(e.get("prev_hash", GENESIS), {"BREAK": True, **rec})
        else:
            expect = record_hash(e.get("prev_hash", GENESIS), rec)
        if e.get("hash") != expect:
            if i not in broken:
                broken.append(i)
        prev = e.get("hash")
    return broken
