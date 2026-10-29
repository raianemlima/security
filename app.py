from __future__ import annotations
import json, os, shutil, tempfile, zipfile
import streamlit as st
from dotenv import load_dotenv

from vuln_agent.ai_review import explain_findings
from vuln_agent.analysis import analyze_code, analyze_feed, analyze_site
from vuln_agent.inputs import allowed_roots_from_env, local_path_enabled, pick_scan_root, resolve_local_path, safe_extract_zip
from vuln_agent.reporting import SEVERITY_ORDER, findings_to_markdown, findings_to_sarif, severity_counts
from vuln_agent.web import parse_extra_headers

load_dotenv()
st.set_page_config(page_title="VulnAgent", page_icon="🛡️", layout="wide")
st.title("🛡️ VulnAgent")
st.caption("Análise defensiva de código e sites • scanners reais + interpretação opcional por IA")

TRIAGE_LABELS = {
    "not_reportable_as_is": "Não reportável como está",
    "needs_impact_validation": "Precisa validar impacto",
    "needs_manual_review": "Precisa de revisão manual",
}


def set_report(report):
    st.session_state.last_report = report
    # An AI review belongs to one report; never show it next to a different one.
    st.session_state.ai_result = None


with st.sidebar:
    st.header("Escopo autorizado")
    st.warning("Use somente código próprio ou sites para os quais você tem autorização expressa.")
    mode = st.radio("Tipo de análise", ["Código / repositório", "Site web", "Feed JSON (odds)"])
    st.divider()
    st.write("Scanners disponíveis")
    st.write("Semgrep:", "✅" if shutil.which("semgrep") else "— não instalado")
    st.write("OSV-Scanner:", "✅" if shutil.which("osv-scanner") else "— não instalado")
    st.write("Análise estática JS/TS:", "✅ integrada")
    st.write("Análise estática Solana/Anchor:", "✅ integrada")
    st.write("Análise de feed JSON (odds):", "✅ integrada")
    st.write("Detecção de segredos:", "✅ integrada (valores mascarados)")
    st.write("IA:", "✅ configurada" if os.getenv("OPENAI_API_KEY") else "— opcional")

if "last_report" not in st.session_state:
    st.session_state.last_report = None

if mode == "Código / repositório":
    st.subheader("Analisar código")
    st.caption("Inclui heurísticas passivas para JavaScript/TypeScript (targetOrigin wildcard, listeners de mensagem sem verificação de origem) e para programas Solana/Anchor em Rust (signatário/autoridade, contas não verificadas, PDA sem bump, CPI, aritmética, init/close). Achados exigem validação manual.")
    sources = ["Pasta local", "Upload ZIP"] if local_path_enabled() else ["Upload ZIP"]
    source = st.radio("Origem", sources, horizontal=True)
    if source == "Pasta local":
        roots = allowed_roots_from_env()
        if roots:
            st.caption("Pastas permitidas: " + ", ".join(str(r) for r in roots))
        local_path = st.text_input("Caminho absoluto da pasta", placeholder=r"C:\projetos\meu-app")
        if st.button("Executar análise de código", type="primary"):
            try:
                path = resolve_local_path(local_path)
            except ValueError as e:
                st.error(str(e))
            else:
                with st.spinner("Executando verificações locais..."):
                    set_report(analyze_code(path))
    else:
        uploaded = st.file_uploader("Envie um ZIP contendo o código", type=["zip"])
        if st.button("Executar análise do ZIP", type="primary"):
            if not uploaded:
                st.error("Envie um arquivo ZIP.")
            else:
                try:
                    with tempfile.TemporaryDirectory(prefix="vulnagent_") as temp_dir:
                        safe_extract_zip(uploaded, temp_dir)
                        with st.spinner("Executando verificações locais..."):
                            set_report(analyze_code(pick_scan_root(temp_dir), uploaded.name))
                except (zipfile.BadZipFile, ValueError, OSError) as e:
                    st.error(f"Não foi possível analisar o ZIP: {e}")
elif mode == "Feed JSON (odds)":
    st.subheader("Análise passiva de feed JSON")
    st.info("Cole um JSON de feed de odds já capturado da sua própria sessão. A análise é offline: "
            "extrai domínios de terceiros, URLs ocultas em base64, proxies com URL embutida e a margem "
            "por mercado. Nenhuma requisição de rede é feita. Um feed público não é, por si só, vulnerabilidade.")
    feed_text = st.text_area("JSON do feed", height=260, placeholder='{"feed": [ ... ]}')
    if st.button("Analisar feed", type="primary"):
        if not feed_text.strip():
            st.error("Cole o JSON do feed.")
        else:
            try:
                with st.spinner("Analisando o feed offline..."):
                    set_report(analyze_feed(feed_text))
            except ValueError as e:
                st.error(str(e))
else:
    st.subheader("Verificação passiva de site")
    url = st.text_input("URL do site autorizado", placeholder="https://meu-dominio.example")
    extra_headers_text = st.text_area(
        "Cabeçalhos de identificação (opcional, um por linha)",
        value=os.getenv("VULNAGENT_EXTRA_HEADERS", ""),
        placeholder="X-HackerOne-Research: seu_usuario",
        help="Use quando o programa exigir que pesquisadores se identifiquem. Credenciais (Cookie, Authorization) e Host/Origin não são aceitos.")
    st.info("A análise faz uma única requisição GET à URL informada, sem seguir redirecionamentos, e verifica TLS, cabeçalhos, CORS e cookies. Não executa exploração.")
    if st.button("Verificar site", type="primary"):
        try:
            extra_headers = parse_extra_headers(extra_headers_text)
            with st.spinner("Verificando resposta HTTP e cabeçalhos..."):
                set_report(analyze_site(url, extra_headers))
        except Exception as e:
            st.error(f"Não foi possível executar a verificação: {e}")

report = st.session_state.last_report
if report:
    st.divider()
    st.subheader("Resultado")
    findings = report["findings"]
    counts = severity_counts(findings)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Achados", len(findings))
    c2.metric("Crítica / Alta", counts.get("Critical", 0) + counts.get("High", 0))
    c3.metric("Média", counts.get("Medium", 0))
    c4.metric("Baixa / Info", counts.get("Low", 0) + counts.get("Info", 0))
    st.caption("Os resultados são indicadores para revisão, não confirmação automática de explorabilidade.")
    for notice in (f for f in findings if f.get("is_notice")):
        st.warning(f"**{notice['title']}.** {notice['description']}\n\n{notice['recommendation']}")
    with st.expander("Status dos scanners e metadados"):
        st.json(report.get("metadata", {}))
    if findings:
        f1, f2 = st.columns([3, 2])
        selected = f1.multiselect("Severidades exibidas", SEVERITY_ORDER,
                                  default=[s for s in SEVERITY_ORDER if counts.get(s)])
        hide_not_reportable = f2.checkbox("Ocultar 'não reportável como está'")
        visible = [f for f in findings
                   if (f.get("severity") if f.get("severity") in SEVERITY_ORDER else "Info") in selected
                   and not (hide_not_reportable and f.get("triage_status") == "not_reportable_as_is")]
        st.caption(f"Exibindo {len(visible)} de {len(findings)} achados, do mais grave ao menos grave.")
        for i, f in enumerate(visible, 1):
            with st.expander(f"{i}. [{f.get('severity','Info')}] {f.get('title','Achado')}"):
                st.write(f.get("description", ""))
                locations = f.get("locations") or ([f["location"]] if f.get("location") else [])
                if locations:
                    st.code("\n".join(locations))
                if f.get("evidence"):
                    st.write("**Evidência:**")
                    st.code(str(f["evidence"])[:5000])
                if f.get("recommendation"):
                    st.write("**Correção sugerida:**", f["recommendation"])
                if f.get("triage_status"):
                    st.caption(f"Triagem: {TRIAGE_LABELS.get(f['triage_status'], f['triage_status'])} — {f.get('triage_reason', '')}")
                st.caption(f"Origem: {f.get('source','heurística')} • Confiança: {f.get('confidence','média')}"
                           + (f" • Regra: {f['rule_id']}" if f.get("rule_id") else ""))
    else:
        st.success("Nenhum achado foi produzido pelos verificadores executados. Isso não garante ausência de vulnerabilidades.")
    left, middle, right = st.columns(3)
    left.download_button("Baixar relatório JSON", json.dumps(report, indent=2, ensure_ascii=False),
                         file_name="vulnagent-report.json", mime="application/json")
    middle.download_button("Baixar relatório Markdown", findings_to_markdown(report),
                           file_name="vulnagent-report.md", mime="text/markdown")
    right.download_button("Baixar SARIF (GitHub code scanning)",
                          json.dumps(findings_to_sarif(report), indent=2, ensure_ascii=False),
                          file_name="vulnagent-report.sarif", mime="application/sarif+json")
    if os.getenv("OPENAI_API_KEY") and findings:
        st.caption("A IA recebe apenas os achados (evidências truncadas e segredos mascarados), nunca o código completo.")
        if st.button("Pedir à IA explicações e prioridades"):
            with st.spinner("A IA está interpretando apenas os achados coletados..."):
                try:
                    st.session_state.ai_result = explain_findings(findings)
                except Exception as e:
                    st.error(f"Falha na análise por IA: {e}")
        if st.session_state.get("ai_result"):
            st.markdown("### Revisão assistida por IA")
            st.markdown(st.session_state.ai_result)
