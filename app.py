from __future__ import annotations
import json, os, tempfile, zipfile
from pathlib import Path
import streamlit as st
from dotenv import load_dotenv

from vuln_agent.scanners import scan_code, scan_site, validate_site_url
from vuln_agent.js_security import scan_javascript_patterns
from vuln_agent.reporting import findings_to_markdown, make_report
from vuln_agent.ai_review import explain_findings

load_dotenv()
st.set_page_config(page_title="VulnAgent", page_icon="🛡️", layout="wide")
st.title("🛡️ VulnAgent")
st.caption("Análise defensiva de código e sites • scanners reais + interpretação opcional por IA")

with st.sidebar:
    st.header("Escopo autorizado")
    st.warning("Use somente código próprio ou sites para os quais você tem autorização expressa.")
    mode = st.radio("Tipo de análise", ["Código / repositório", "Site web"])
    st.divider()
    st.write("Scanners disponíveis")
    st.write("Semgrep:", "✅" if __import__("shutil").which("semgrep") else "— não instalado")
    st.write("OSV-Scanner:", "✅" if __import__("shutil").which("osv-scanner") else "— não instalado")
    st.write("Análise estática JS/TS:", "✅ integrada")
    st.write("IA:", "✅ configurada" if os.getenv("OPENAI_API_KEY") else "— opcional")

if "last_report" not in st.session_state:
    st.session_state.last_report = None

if mode == "Código / repositório":
    st.subheader("Analisar código")
    st.caption("Inclui heurísticas passivas para bundles JavaScript/TypeScript: targetOrigin wildcard e possíveis fallbacks de origem. Achados exigem validação manual.")
    source = st.radio("Origem", ["Pasta local", "Upload ZIP"], horizontal=True)
    root = None
    temp_dir = None
    if source == "Pasta local":
        local_path = st.text_input("Caminho absoluto da pasta", placeholder=r"C:\projetos\meu-app")
        if st.button("Executar análise de código", type="primary"):
            if not local_path.strip():
                st.error("Informe o caminho da pasta.")
            else:
                p = Path(local_path.strip()).expanduser().resolve()
                if not p.is_dir():
                    st.error("A pasta informada não existe ou não é uma pasta.")
                else:
                    with st.spinner("Executando verificações locais..."):
                        findings, meta = scan_code(p)
                        findings.extend(scan_javascript_patterns(p))
                        meta.setdefault("scanner_status", {})["javascript-static"] = "concluído"
                        st.session_state.last_report = make_report("code", str(p), findings, meta)
    else:
        uploaded = st.file_uploader("Envie um ZIP contendo o código", type=["zip"])
        if st.button("Executar análise do ZIP", type="primary"):
            if not uploaded:
                st.error("Envie um arquivo ZIP.")
            else:
                try:
                    temp_dir = tempfile.TemporaryDirectory(prefix="vulnagent_")
                    dest = Path(temp_dir.name).resolve()
                    with zipfile.ZipFile(uploaded) as zf:
                        for member in zf.infolist():
                            target = (dest / member.filename).resolve()
                            if dest != target and dest not in target.parents:
                                raise ValueError("ZIP contém caminho inseguro (path traversal).")
                        zf.extractall(dest)
                    # Se o ZIP tiver uma única pasta raiz, analise-a.
                    children = list(dest.iterdir())
                    scan_root = children[0] if len(children) == 1 and children[0].is_dir() else dest
                    with st.spinner("Executando verificações locais..."):
                        findings, meta = scan_code(scan_root)
                        findings.extend(scan_javascript_patterns(scan_root))
                        meta.setdefault("scanner_status", {})["javascript-static"] = "concluído"
                        st.session_state.last_report = make_report("code", uploaded.name, findings, meta)
                except (zipfile.BadZipFile, ValueError, OSError) as e:
                    st.error(f"Não foi possível analisar o ZIP: {e}")
                finally:
                    if temp_dir:
                        temp_dir.cleanup()
else:
    st.subheader("Verificação passiva de site")
    url = st.text_input("URL do site autorizado", placeholder="https://meu-dominio.example")
    st.info("A análise faz uma requisição GET à página inicial, não segue redirecionamentos para outro host e verifica cabeçalhos/TLS. Não executa exploração.")
    if st.button("Verificar site", type="primary"):
        try:
            safe_url = validate_site_url(url)
            with st.spinner("Verificando resposta HTTP e cabeçalhos..."):
                findings, meta = scan_site(safe_url)
                st.session_state.last_report = make_report("site", safe_url, findings, meta)
        except Exception as e:
            st.error(f"Não foi possível executar a verificação: {e}")

report = st.session_state.last_report
if report:
    st.divider()
    st.subheader("Resultado")
    findings = report["findings"]
    counts = {}
    for f in findings:
        sev = f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Achados", len(findings))
    c2.metric("Alta", counts.get("High", 0))
    c3.metric("Média", counts.get("Medium", 0))
    c4.metric("Baixa / Info", counts.get("Low", 0) + counts.get("Info", 0))
    st.caption("Os resultados são indicadores para revisão, não confirmação automática de explorabilidade.")
    if findings:
        for i, f in enumerate(findings, 1):
            with st.expander(f"{i}. [{f.get('severity','Info')}] {f.get('title','Achado')}"):
                st.write(f.get("description", ""))
                if f.get("location"):
                    st.code(f["location"])
                if f.get("evidence"):
                    st.write("**Evidência:**")
                    st.code(str(f["evidence"])[:5000])
                if f.get("recommendation"):
                    st.write("**Correção sugerida:**", f["recommendation"])
                if f.get("triage_status"):
                    st.caption(f"Triagem: {f['triage_status']} — {f.get('triage_reason', '')}")
                st.caption(f"Origem: {f.get('source','heurística')} • Confiança: {f.get('confidence','média')}")
    else:
        st.success("Nenhum achado foi produzido pelos verificadores executados. Isso não garante ausência de vulnerabilidades.")
    left, right = st.columns(2)
    json_data = json.dumps(report, indent=2, ensure_ascii=False)
    md_data = findings_to_markdown(report)
    left.download_button("Baixar relatório JSON", json_data, file_name="vulnagent-report.json", mime="application/json")
    right.download_button("Baixar relatório Markdown", md_data, file_name="vulnagent-report.md", mime="text/markdown")
    if os.getenv("OPENAI_API_KEY") and findings:
        if st.button("Pedir à IA explicações e prioridades"):
            with st.spinner("A IA está interpretando apenas os achados coletados..."):
                try:
                    st.session_state.ai_result = explain_findings(findings)
                except Exception as e:
                    st.error(f"Falha na análise por IA: {e}")
        if st.session_state.get("ai_result"):
            st.markdown("### Revisão assistida por IA")
            st.markdown(st.session_state.ai_result)
