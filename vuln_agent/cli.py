"""Command line: ``python -m vuln_agent code <pasta|arquivo.zip>`` or ``python -m vuln_agent site <url>``."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import zipfile
from pathlib import Path

from dotenv import load_dotenv

from vuln_agent.analysis import analyze_code, analyze_site
from vuln_agent.inputs import pick_scan_root, resolve_local_path, safe_extract_zip
from vuln_agent.reporting import findings_to_markdown, findings_to_sarif, severity_rank
from vuln_agent.web import extra_headers_from_env, parse_extra_headers

FAIL_LEVELS = {"none": None, "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vuln_agent",
        description="VulnAgent: análise defensiva de código e sites. Use somente em alvos próprios ou autorizados.")
    sub = parser.add_subparsers(dest="command", required=True)
    code = sub.add_parser("code", help="Analisa uma pasta de código ou um arquivo ZIP.")
    code.add_argument("path", help="Pasta do repositório ou arquivo .zip")
    site = sub.add_parser("site", help="Verificação web passiva de uma URL autorizada.")
    site.add_argument("url")
    site.add_argument("-H", "--header", action="append", default=[], metavar="'Nome: valor'",
                      help="Cabeçalho de identificação exigido pelo programa (repetível). "
                           "Padrão: VULNAGENT_EXTRA_HEADERS.")
    for command in (code, site):
        command.add_argument("-f", "--format", choices=("markdown", "json", "sarif"), default="markdown")
        command.add_argument("-o", "--output", help="Arquivo de saída (padrão: saída padrão).")
        command.add_argument("--fail-on", choices=tuple(FAIL_LEVELS), default="none",
                             help="Retorna código 1 se existir achado com esta severidade ou maior "
                                  "(ignora achados triados como 'não reportável como está').")
    return parser


def _analyze_code_path(path: Path) -> dict:
    if path.is_file() and path.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory(prefix="vulnagent_") as tmp:
            safe_extract_zip(path, tmp)
            return analyze_code(pick_scan_root(tmp), path.name)
    return analyze_code(resolve_local_path(str(path), allowed_roots=[]))


def render(report: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if fmt == "sarif":
        return json.dumps(findings_to_sarif(report), indent=2, ensure_ascii=False) + "\n"
    return findings_to_markdown(report)


def should_fail(report: dict, level: str) -> bool:
    threshold = FAIL_LEVELS[level]
    if threshold is None:
        return False
    return any(severity_rank(f.get("severity")) <= severity_rank(threshold)
               and f.get("triage_status") != "not_reportable_as_is"
               for f in report.get("findings", []))


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "code":
            report = _analyze_code_path(Path(args.path))
        else:
            headers = parse_extra_headers(args.header) if args.header else extra_headers_from_env()
            report = analyze_site(args.url, headers)
    except (ValueError, RuntimeError, OSError, zipfile.BadZipFile) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    output = render(report, args.format)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 1 if should_fail(report, args.fail_on) else 0
