"""Heuristic, read-only checks for Solana / Anchor programs (Rust).

These flag well-known audit *indicators* in on-chain program source — missing signer or
authority checks, unchecked accounts, PDA validation, CPI handling, arithmetic, and account
init/close. They are review signals, never confirmed exploitable vulnerabilities, and prove
nothing on their own: the data flow, the account constraints and the instruction sequencing
must be read by a human. The scanner never executes code and never touches any network or chain.

Point it at the program source you are authorised to audit (its repository); then validate every
finding against a concrete security impact before reporting, as a responsible-disclosure program
requires.
"""
from __future__ import annotations

import re
from itertools import islice
from pathlib import Path

from vuln_agent.findings import make_finding
from vuln_agent.fs import iter_files

RUST_EXTENSIONS = {".rs"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "target"}
MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
MAX_MATCHES = 8
STRUCT_SCAN_LIMIT = 20_000
LEAD_WINDOW = 800

_TRIAGE = {
    "triage_status": "needs_manual_review",
    "triage_reason": "Indicador estático em programa on-chain; confirme assinaturas, constraints, " +
                     "PDAs, fluxo de dados e impacto concreto antes de classificar como vulnerabilidade.",
}

# Account field names that usually carry privilege and therefore must be a Signer or be bound
# by a constraint (has_one / address / constraint / signer).
_AUTHORITY_NAME = re.compile(
    r"(?i)(authorit|admin|owner|signer|payer|manager|governor|updater|minter|burner|vault_authority|delegate)")
_UNCHECKED_TYPE = re.compile(r"\b(?:AccountInfo|UncheckedAccount)\b")
_CHECK_DOC = re.compile(r"///?\s*CHECK", re.IGNORECASE)
_CONSTRAINED = re.compile(r"\b(?:has_one|constraint|address|seeds)\b|\bsigner\b")
# Amount-like identifiers whose accounting bugs matter (sale/vesting/burn).
_AMOUNT_ASSIGN = re.compile(
    r"(?i)\b([a-z_]*(?:amount|balance|lamports|supply|total|allocation|allocated|vested|deposit|"
    r"deposited|claimed|claimable|remaining|quota|cap|limit|price|contribution|refund|burned|minted)"
    r"[a-z_]*)\s*(\+=|-=|\*=)(?!=)")

# (regex, title, severity, description, recommendation, rule_id)
_PATTERNS: list[tuple[re.Pattern[str], str, str, str, str, str]] = [
    (
        re.compile(r"\binit_if_needed\b"),
        "Uso de init_if_needed (risco de reinicialização)",
        "Medium",
        "init_if_needed reexecuta a inicialização se a conta já existir. Sem um guard de estado, uma " +
        "instrução pode ser chamada de novo para redefinir saldos, autoridade ou fase (sale/vesting/burn).",
        "Garanta um campo de estado que impeça reinicialização; confirme a feature init-if-needed e trate " +
        "explicitamente o caso 'conta já inicializada'.",
        "vulnagent.solana.init-if-needed",
    ),
    (
        re.compile(r"\binvoke_signed\s*\("),
        "CPI com invoke_signed (revisar seeds e programa de destino)",
        "Medium",
        "invoke_signed assina com seeds de PDA. Se o programa de destino ou as contas não forem validados, " +
        "um atacante pode redirecionar a CPI; se as seeds derivarem de entrada, a assinatura do PDA pode ser abusada.",
        "Valide o program id de destino e todas as contas da CPI; derive as seeds apenas de dados confiáveis e " +
        "verifique o bump canônico.",
        "vulnagent.solana.invoke-signed",
    ),
    (
        re.compile(r"(?<![\w_])invoke\s*\("),
        "CPI com invoke (revisar programa e contas de destino)",
        "Low",
        "Uma CPI é feita com invoke. Sem validar o program id e as contas passadas, a chamada pode ir a um " +
        "programa substituído pelo atacante (manipulação de CPI).",
        "Confirme o program id de destino (por tipo Program<'info, T> ou comparação de endereço) e valide as contas.",
        "vulnagent.solana.invoke",
    ),
    (
        re.compile(r"token(?:_2022)?::(?:transfer|transfer_checked|mint_to|burn|set_authority)\b|\bTransfer\s*\{"),
        "Transferência/mint/burn de tokens via CPI (revisar autoridade)",
        "Low",
        "Há uma operação de token SPL (transfer/mint_to/burn/set_authority). O ponto crítico é quem assina: " +
        "a autoridade deve ser o signatário correto ou um PDA do próprio programa, nunca uma conta controlável.",
        "Verifique que a authority do token é validada (Signer ou PDA do programa com seeds/bump) e que o " +
        "montante respeita limites e contabilidade.",
        "vulnagent.solana.spl-token-op",
    ),
    (
        re.compile(r"\*\*\s*[\w.]+\.(?:try_borrow_mut_lamports|lamports)\s*\(\s*\)?"),
        "Manipulação direta de lamports (fechamento/saque manual)",
        "Medium",
        "O código mexe diretamente nos lamports de uma conta (padrão de fechamento ou saque manual). " +
        "Fechamento manual mal feito permite reutilização da conta (revival) ou drenagem não autorizada.",
        "Prefira a constraint `close = destino` do Anchor; se for manual, zere os dados, transfira todos os " +
        "lamports e impeça reuso. Garanta que a autoridade de fechamento/saque é verificada.",
        "vulnagent.solana.manual-lamports",
    ),
    (
        re.compile(r"Clock::get\s*\(\s*\)|unix_timestamp|Clock::from_account_info"),
        "Dependência de tempo (TGE/cliff/vesting) — revisar fonte e comparações",
        "Low",
        "O programa usa o relógio da rede. Em cronogramas de vesting/TGE, erros de comparação (>, >=) ou " +
        "uso de Clock vindo de conta não confiável permitem saque antecipado ou fora do cronograma.",
        "Use Clock::get() (sysvar confiável), revise os limites das comparações de tempo e teste os marcos " +
        "de cliff/TGE/fim de vesting.",
        "vulnagent.solana.time-dependent",
    ),
]


def _balanced_block(text: str, open_brace: int) -> str:
    """Return the brace-balanced body starting at ``open_brace`` (bounded)."""
    depth = 0
    end = min(len(text), open_brace + STRUCT_SCAN_LIMIT)
    for i in range(open_brace, end):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:i + 1]
    return text[open_brace:end]


_ACCOUNTS_STRUCT = re.compile(
    r"#\[derive\([^)]{0,200}\bAccounts\b[^)]{0,200}\)\]\s*(?:#\[[^\]]{0,200}\]\s*)*"
    r"pub\s+struct\s+\w+[^\{]{0,200}\{")
_FIELD = re.compile(r"pub\s+(?P<name>\w+)\s*:\s*(?P<ty>[A-Za-z_][^,\n{}]{0,200}?)\s*,")


def _iter_account_fields(text: str):
    """Yield (absolute_offset, name, type, lead) for fields of every #[derive(Accounts)] struct."""
    for struct in _ACCOUNTS_STRUCT.finditer(text):
        body_start = struct.end() - 1
        body = _balanced_block(text, body_start)
        for field in _FIELD.finditer(body):
            offset = body_start + field.start()
            lead = text[max(0, offset - LEAD_WINDOW):offset]
            yield offset, field.group("name"), field.group("ty"), lead


_ACCOUNT_ATTR_OPEN = re.compile(r"#\[account\(")


def _iter_account_attrs(text: str):
    """Yield (start, attribute_text) for each #[account(...)] with balanced parentheses.

    A naive regex stops at the first ``)]``, which occurs inside ``seeds = [b"x", key().as_ref()]``;
    balancing the parens captures the whole attribute (including a trailing ``bump``).
    """
    for opener in _ACCOUNT_ATTR_OPEN.finditer(text):
        depth, end = 0, min(len(text), opener.end() + 600)
        for i in range(opener.end() - 1, end):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    yield opener.start(), text[opener.start():i + 1]
                    break


def _lead_attr(lead: str) -> str:
    """The nearest #[account(...)] attribute preceding a field, if any."""
    attrs = [attr for _start, attr in _iter_account_attrs(lead)]
    return attrs[-1] if attrs else ""


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _finding(title, severity, description, recommendation, rule_id, location, evidence):
    return make_finding(title, severity, description, location, evidence, recommendation,
                        "heurística Solana/Anchor", "baixa; exige revisão manual",
                        rule_id=rule_id, **_TRIAGE)


_PROGRAM_CARGO = re.compile(r"solana-program|anchor-lang|solana_program|cdylib")


def _scan_cargo_overflow(path: Path, text: str, rel: str) -> list[dict]:
    # Only on-chain program crates: a wrap in a build tool or test crate is not a chain bug.
    if path.name != "Cargo.toml" or "overflow-checks" in text or not _PROGRAM_CARGO.search(text):
        return []
    return [_finding(
        "Cargo.toml sem overflow-checks (aritmética pode fazer wrap em release)", "Medium",
        "Sem `overflow-checks = true`, a aritmética de inteiros faz wrap silencioso em build de release em vez " +
        "de entrar em panic. Em contabilidade de sale/vesting/burn, isso vira saldo incorreto ou bypass de limite.",
        "Adicione `overflow-checks = true` em [profile.release] e prefira operações checked_/saturating_.",
        "vulnagent.solana.cargo-overflow-checks", rel, "overflow-checks ausente em Cargo.toml")]


def _scan_rust(text: str, rel: str) -> list[dict]:
    findings = []

    def location(index):
        return f"{rel}:{_line_of(text, index)}"

    def snippet(match):
        return re.sub(r"\s+", " ", match.group(0)).strip()[:300]

    for pattern, title, severity, description, recommendation, rule_id in _PATTERNS:
        for match in islice(pattern.finditer(text), MAX_MATCHES):
            findings.append(_finding(title, severity, description, recommendation, rule_id,
                                     location(match.start()), snippet(match)))

    for match in islice(_AMOUNT_ASSIGN.finditer(text), MAX_MATCHES):
        window = text[match.start():match.end() + 80]
        if "checked_" in window or "saturating_" in window:
            continue
        line_start = text.rfind("\n", 0, match.start()) + 1
        line = text[line_start:text.find("\n", match.start())]
        if line.lstrip().startswith("//"):
            continue
        findings.append(_finding(
            "Aritmética sem verificação em valor de saldo/montante", "Medium",
            "Uma variável de saldo/montante é atualizada com +=/-=/*= sem checked_/saturating_. Overflow ou " +
            "underflow aqui corrompe a contabilidade (pagamento duplo, sobreassinatura, bypass de limite).",
            "Use checked_add/checked_sub/checked_mul (ou saturating_*) e trate o estouro explicitamente.",
            "vulnagent.solana.unchecked-arithmetic", location(match.start()), snippet(match)))

    # Native (non-Anchor) handlers: iterating accounts without any signer check.
    native_iter = re.search(r"next_account_info\s*\(", text)
    if native_iter and ".is_signer" not in text:
        match = native_iter
        findings.append(_finding(
            "Handler lê contas sem verificar is_signer", "High",
            "O código percorre contas (next_account_info) mas nunca checa `.is_signer`. Instruções privilegiadas " +
            "(saque, queima, mudança de autoridade) ficam acessíveis a qualquer chamador.",
            "Verifique `account.is_signer` para toda autoridade exigida antes de executar a ação.",
            "vulnagent.solana.native-missing-signer", location(match.start()), snippet(match)))

    seen_authority = set()
    for offset, name, ty, lead in _iter_account_fields(text):
        if not _UNCHECKED_TYPE.search(ty):
            continue
        attr = _lead_attr(lead)
        has_check_doc = bool(_CHECK_DOC.search(lead))
        if not has_check_doc:
            findings.append(_finding(
                "Conta não verificada sem comentário /// CHECK", "Medium",
                f"O campo `{name}: {ty.strip()}` é uma conta sem tipo (AccountInfo/UncheckedAccount) e não tem o " +
                "comentário `/// CHECK:` que o Anchor exige. Contas sem tipo não têm owner/discriminator " +
                "verificados, abrindo espaço para substituição de conta.",
                "Prefira um tipo concreto (Account<'info, T>, Program, Signer). Se precisar ser sem tipo, " +
                "documente com `/// CHECK:` e valide owner, endereço ou seeds manualmente.",
                "vulnagent.solana.unchecked-account", f"{rel}:{_line_of(text, offset)}", f"pub {name}: {ty.strip()}"))
        if _AUTHORITY_NAME.search(name) and not _CONSTRAINED.search(attr) and offset not in seen_authority:
            seen_authority.add(offset)
            findings.append(_finding(
                "Conta de autoridade sem Signer nem constraint", "High",
                f"O campo de autoridade `{name}` é AccountInfo/UncheckedAccount e o #[account(...)] não tem " +
                "signer/has_one/constraint/address. Não há garantia de que o chamador é a autoridade legítima.",
                "Use Signer<'info> ou vincule a uma autoridade armazenada via has_one/address/constraint.",
                "vulnagent.solana.authority-without-check", f"{rel}:{_line_of(text, offset)}",
                f"pub {name}: {ty.strip()}"))

    # PDA seeds declared without a bump constraint.
    for start, attr in islice(_iter_account_attrs(text), 200):
        if re.search(r"\bseeds\s*=", attr) and not re.search(r"\bbump\b", attr):
            evidence = re.sub(r"\s+", " ", attr).strip()[:300]
            findings.append(_finding(
                "PDA com seeds sem bump canônico", "Medium",
                "Uma constraint `seeds = [...]` não acompanha `bump`. Sem fixar o bump canônico, contas com bump " +
                "alternativo podem passar na validação (substituição de PDA).",
                "Adicione `bump` (ou `bump = conta.bump` armazenado) para fixar o PDA canônico.",
                "vulnagent.solana.pda-without-bump", location(start), evidence))

    return _dedupe(findings)


def _dedupe(findings: list[dict]) -> list[dict]:
    seen, unique = set(), []
    for f in findings:
        key = (f["rule_id"], f["location"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_solana_programs(root: Path) -> list[dict]:
    """Scan local Rust/Anchor source for Solana program audit indicators (no execution)."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("A origem do código não é uma pasta.")
    findings: list[dict] = []
    accept = lambda p: p.suffix.lower() in RUST_EXTENSIONS or p.name == "Cargo.toml"
    for path in iter_files(root, accept, skip_dirs=SKIP_DIRS, max_files=MAX_FILES, max_bytes=MAX_FILE_BYTES):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        if path.name == "Cargo.toml":
            findings.extend(_scan_cargo_overflow(path, text, rel))
        else:
            findings.extend(_scan_rust(text, rel))
    return findings
