# -*- coding: utf-8 -*-
"""아레나 제출 검사(2026-10-28). 배포(제출) 직전에 응시 레포의 .arena/ 기록을 검사하고, 실패면 종료 코드 1.

검사 넷
  1 기록 있음·늘었음: .arena/*.jsonl 줄이 있고, 기준점(직전 제출 커밋 또는 기본 브랜치)보다 늘었으며
    기준점에 있던 줄은 앞부분에 그대로 남아 있음(추가만 허용)
  2 해시 이어짐: 파일마다 chain_util.verify_chain. 「기록 끊김」(kind=break) 줄은 허용하고 개수만 보고
  3 비밀값 남음 없음: .arena/ 아래 모든 파일을 mask_secrets 규칙으로 다시 훑어 가리지 않은 것이 있으면 실패
  4 서버 앵커(선택): --anchor-url 또는 ARENA_ANCHOR_URL이 있을 때만. 없으면 건너뜀

보안: 이 파일과 chain_util.py·mask_secrets.py는 응시 레포가 아니라 우리 쪽 고정 위치에서 받아
`python3 -I`로 실행한다(README). 응시 레포의 파일은 데이터로만 읽고 실행·import하지 않는다.
python3 표준 라이브러리만 쓴다.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
# chain_util·mask_secrets는 이 파일 옆(배포용 고정 레포) 또는 두 단계 위(AI대화훅 원본 폴더)에서 찾는다
for _p in (os.path.normpath(os.path.join(_HERE, "..", "..")), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from chain_util import verify_chain  # noqa: E402
from mask_secrets import RULES  # noqa: E402

PASS, FAIL, SKIP = "통과", "실패", "건너뜀"
MASK_MARK = "[가려짐"  # mask_secrets가 넣는 자리표시. 이미 가린 자리는 다시 걸려도 남은 비밀값이 아님


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    return r.returncode, r.stdout.decode("utf-8", "replace")


def jsonl_lines(text):
    return [ln for ln in text.splitlines() if ln.strip()]


def current_logs(repo):
    """{도구: [줄,...]} 지금 작업 트리의 .arena/*.jsonl"""
    d = os.path.join(repo, ".arena")
    out = {}
    if os.path.isdir(d):
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if name.endswith(".jsonl") and os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as f:
                    out[name[:-6]] = jsonl_lines(f.read())
    return out


def base_logs(repo, base):
    code, out = git(repo, "ls-tree", "--name-only", base, ".arena/")
    logs = {}
    if code != 0:
        return logs
    for path in out.splitlines():
        name = path.split("/", 1)[-1]
        if "/" in name or not name.endswith(".jsonl"):
            continue
        _, text = git(repo, "show", "%s:%s" % (base, path))
        logs[name[:-6]] = jsonl_lines(text)
    return logs


def resolve_base(repo, base):
    """기준점 커밋을 돌려줌. None=기준점 없음(첫 제출), False=지정했는데 못 찾음"""
    if base is None:
        code, out = git(repo, "rev-parse", "--verify", "-q", "HEAD~1^{commit}")
        return out.strip() if code == 0 else None
    if base == "none" or set(base) <= {"0"}:  # push 이벤트의 새 브랜치는 before가 0000…
        return None
    code, out = git(repo, "rev-parse", "--verify", "-q", base + "^{commit}")
    return out.strip() if code == 0 else False


def check_grown(repo, logs, base):
    total = sum(len(v) for v in logs.values())
    if total == 0:
        return FAIL, "기록 없음(.arena/*.jsonl 줄 0)", []
    b = resolve_base(repo, base)
    if b is False:
        return FAIL, "기준점 %s 를 찾지 못함" % base, []
    if b is None:
        return PASS, "기준점 없음(첫 제출), 기록 %d줄" % total, []
    old = base_logs(repo, b)
    old_total = sum(len(v) for v in old.values())
    problems = []
    for tool, lines in old.items():
        now = logs.get(tool, [])
        if now[: len(lines)] != lines:
            problems.append("%s.jsonl: 기준점 %d줄이 앞부분에 그대로 남아 있지 않음(지움·고침·다시 만듦)" % (tool, len(lines)))
    if problems:
        return FAIL, "기준점 %s 이후 앞 기록이 바뀜" % b[:7], problems
    if total <= old_total:
        return FAIL, "안 늘어남(기준점 %s %d줄, 지금 %d줄)" % (b[:7], old_total, total), []
    return PASS, "기준점 %s %d줄에서 %d줄로 늘어남" % (b[:7], old_total, total), []


def parse_entries(lines):
    entries, bad = [], []
    for i, ln in enumerate(lines, 1):
        try:
            e = json.loads(ln)
            if not isinstance(e, dict):
                raise ValueError
            entries.append(e)
        except ValueError:
            bad.append(i)
    return entries, bad


def check_chain(logs):
    if not logs:
        return FAIL, "검사할 기록 없음", []
    problems, breaks, n = [], 0, 0
    for tool, lines in logs.items():
        entries, bad = parse_entries(lines)
        if bad:
            problems.append("%s.jsonl: JSON으로 못 읽는 줄 %s" % (tool, bad))
            continue
        broken = verify_chain(entries)
        if broken:
            problems.append("%s.jsonl: 해시 끊김 %s번째 줄" % (tool, [i + 1 for i in broken]))
        b = sum(1 for e in entries if e.get("kind") == "break")
        breaks += b
        n += len(entries)
    if problems:
        return FAIL, "끊김 있음(파일 %d개 중 %d개)" % (len(logs), len(problems)), problems
    return PASS, "파일 %d개 %d줄 이어짐, 「기록 끊김」 줄 %d개" % (len(logs), n, breaks), []


def find_secrets(text):
    """가리지 않은 비밀값 꼴의 규칙 이름 목록(값 자체는 돌려주지 않음)"""
    hits = []
    for name, pattern, _ in RULES:
        for m in pattern.finditer(text):
            if MASK_MARK not in m.group(0):
                hits.append(name)
    return hits


def walk_strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, list):
        for x in o:
            yield from walk_strings(x)
    elif isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from walk_strings(v)


def check_secrets(repo):
    d = os.path.join(repo, ".arena")
    if not os.path.isdir(d):
        return FAIL, "검사할 .arena/ 없음", []
    problems, files = [], 0
    for root, _, names in os.walk(d):
        for name in sorted(names):
            p = os.path.join(root, name)
            rel = os.path.relpath(p, repo)
            files += 1
            with open(p, encoding="utf-8", errors="replace") as f:
                text = f.read()
            chunks = []  # (줄 번호, 훑을 글)
            if name.endswith(".jsonl"):
                for i, ln in enumerate(text.splitlines(), 1):
                    try:
                        chunks += [(i, s) for s in walk_strings(json.loads(ln))]
                    except ValueError:
                        chunks.append((i, ln))
            else:
                chunks.append((None, text))
            for i, s in chunks:
                for rule in find_secrets(s):
                    problems.append("%s%s: %s" % (rel, "" if i is None else ":%d" % i, rule))
    if problems:
        return FAIL, "가리지 않은 비밀값 꼴 %d곳" % len(problems), problems
    return PASS, "파일 %d개에서 남은 비밀값 꼴 없음" % files, []


def check_anchor(logs, url):
    if not url:
        return SKIP, "서버 앵커 주소 없음(ARENA_ANCHOR_URL 미설정)", []
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            anchors = json.loads(r.read().decode("utf-8"))
    except Exception as e:  # 확인 못 하면 통과시키지 않음
        return FAIL, "서버 앵커를 못 읽음: %s" % type(e).__name__, []
    problems = []
    for tool in sorted(set(anchors) | set(logs)):
        entries, _ = parse_entries(logs.get(tool, []))
        last = entries[-1].get("hash") if entries else None
        if tool not in anchors:
            problems.append("%s: 서버에 맡긴 해시 없음" % tool)
        elif last != anchors[tool]:
            problems.append("%s: 마지막 해시가 서버와 다름(꼬리 잘림·다시 만듦 의심)" % tool)
    if problems:
        return FAIL, "서버 앵커와 다름", problems
    return PASS, "도구 %d개 마지막 해시가 서버와 같음" % len(anchors), []


def main(argv=None):
    ap = argparse.ArgumentParser(description="아레나 제출 검사")
    ap.add_argument("--repo", default=".", help="응시 레포 경로")
    ap.add_argument("--base", default=None, help="기준점 커밋(생략=HEAD~1, none=기준점 없음)")
    ap.add_argument("--anchor-url", default=os.environ.get("ARENA_ANCHOR_URL"),
                    help="서버 앵커 JSON 주소({도구: 마지막 hash})")
    a = ap.parse_args(argv)
    repo = os.path.abspath(a.repo)
    logs = current_logs(repo)

    results = [
        ("1 기록 있음·늘었음",) + check_grown(repo, logs, a.base),
        ("2 해시 이어짐",) + check_chain(logs),
        ("3 비밀값 남음 없음",) + check_secrets(repo),
        ("4 서버 앵커",) + check_anchor(logs, a.anchor_url),
    ]
    print("| 검사 | 결과 | 내용 |")
    print("|---|---|---|")
    for name, status, summary, _ in results:
        print("| %s | %s | %s |" % (name, status, summary))
    for name, status, _, details in results:
        for d in details:
            print("- [%s] %s" % (name, d))
    failed = any(r[1] == FAIL for r in results)
    print("\n제출 %s" % ("불가" if failed else "가능"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
