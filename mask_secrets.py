# -*- coding: utf-8 -*-
"""AI 도구 기록을 서버로 보내기 전에 비밀번호·접속 키 꼴을 자동으로 가리는 모듈(2026-10-27, 예비작업 3).

배경: 지금 코드베이스에는 AI 대화 수집 훅 자체가 아직 구현돼 있지 않다(평가문제/AI대화기록_받는길_v3*.md는
설계·결정 문서뿐, 실제 전송 스크립트는 없음, 10/27 확인). 그래서 "훅에 넣은 사본"을 만드는 대신, 훅이 생기면
그 전송 직전에 호출할 독립 함수로 만들어 둔다. 실제 훅을 만들 때는 보내기 직전에
`mask_secrets.mask(text)`를 한 번 거치면 된다.

규칙 출처: gitleaks 기본 규칙(github.com/gitleaks/gitleaks, generic-api-key·aws·github·slack·private-key 항목),
detect-secrets 기본 플러그인(Yelp/detect-secrets, KeywordDetector·Base64HighEntropyString),
각 발급사 공개 문서의 키 형식(OpenAI·Anthropic·Google·GitHub·Slack·AWS).
"""
import re

RULES = [
    # (이름, 정규식, 바꿀 자리)
    ("AWS 접근 키 ID", re.compile(r"AKIA[0-9A-Z]{16}"), "[가려짐:AWS키]"),
    ("AWS 비밀 키(이름 근처)", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"), "aws_secret_access_key=[가려짐:AWS비밀]"),
    ("Anthropic API 키", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"), "[가려짐:Anthropic키]"),
    ("OpenAI API 키", re.compile(r"sk-(proj-)?[A-Za-z0-9]{20,}"), "[가려짐:OpenAI키]"),
    ("GitHub 토큰", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"), "[가려짐:GitHub토큰]"),
    ("Google API 키", re.compile(r"AIza[0-9A-Za-z\-_]{30,45}"), "[가려짐:Google키]"),
    ("Slack 토큰", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "[가려짐:Slack토큰]"),
    ("Slack 웹훅 URL", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+"), "[가려짐:Slack웹훅]"),
    ("개인 키 블록", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "[가려짐:개인키블록]"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), "[가려짐:JWT]"),
    ("Bearer 토큰", re.compile(r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_.=]+"), "Authorization: Bearer [가려짐:토큰]"),
    ("DB 연결 문자열(비밀번호 포함)", re.compile(r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?)://[^:\s]+:[^@\s]+@[^\s'\"]+"), "[가려짐:DB연결문자열]"),
    # 변수명은 실제 .env 관례대로 대문자만 매칭(소문자 일반 코드 변수와 안 겹치게), 값이 함수 호출 꼴이면 뺌
    (".env 식 비밀 값", re.compile(r"(?m)^(?=[A-Z])([A-Z0-9_]*(SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|PASSWORD|PASSWD|PWD)[A-Z0-9_]*)\s*[:=]\s*['\"]?(?!\w+\()[^\s'\"]{4,}['\"]?"), r"\1=[가려짐]"),
    ("비밀번호 문구(한글)", re.compile(r"비밀\s*번호\s*[:：=]\s*(?!\w+\()\S+"), "비밀번호: [가려짐]"),
    ("password 문구(영문)", re.compile(r"(?i)\bpassword\s*[:=]\s*(?!\w+\()\S+"), "password: [가려짐]"),
]

# 코드에 흔한 거짓양성 방지: 변수 선언에 플레이스홀더만 있는 줄(예: SECRET_KEY = "")은 애초에 \S+{4,} 조건에서 걸러짐(빈 문자열 제외)


def mask(text: str):
    """text를 가린 결과와, 룰별로 몇 번 바뀌었는지 함께 돌려줌."""
    counts = {}
    out = text
    for name, pattern, repl in RULES:
        out, n = pattern.subn(repl, out)
        if n:
            counts[name] = n
    return out, counts
