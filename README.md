# VulnAgent — análise defensiva de código e sites

MVP local com painel Streamlit, integração CI do GitHub Actions e scanners reais opcionais.
**Uso autorizado:** analise somente repositórios e sites que você controla ou para os quais possui autorização expressa.

## Recursos
- Upload de ZIP ou análise de pasta local de código, pelo painel ou pela linha de comando.
- SAST com Semgrep (quando instalado) e verificação de dependências com OSV-Scanner (quando instalado). O OSV gera um achado por pacote vulnerável, com IDs/CVEs, severidade CVSS e versões corrigidas.
- Regras próprias com `rule_id`: eval, SQL montado por concatenação/f-string/`%` (consultas parametrizadas **não** são sinalizadas), innerHTML/`dangerouslySetInnerHTML`/`document.write`, `new Function`, `shell=True`/`os.system`, desserialização insegura (pickle, `yaml.load` sem SafeLoader), JWT sem verificação, TLS desativado, MD5/SHA-1, debug e CORS amplo.
- Detecção de segredos (AWS, GitHub, Slack, Stripe, OpenAI, Anthropic, Google, JWT, chaves privadas, atribuições como `SECRET_KEY = "..."`) e de arquivos `.env`/`.env.*`. **Os valores são sempre mascarados** no painel, nos relatórios e no que vai para a IA.
- Heurísticas estáticas para JavaScript/TypeScript: `postMessage` com `targetOrigin: "*"`, listeners de `message` sem verificação de `event.origin` e possíveis fallbacks de origem com `document.referrer`. Esses sinais exigem revisão manual e não são prova automática de vulnerabilidade.
- Heurísticas estáticas para programas **Solana/Anchor** (Rust): contas de autoridade sem `Signer`/constraint, `AccountInfo`/`UncheckedAccount` sem `/// CHECK`, PDA com `seeds` sem `bump`, `invoke`/`invoke_signed` e operações de token SPL para revisão de autoridade/CPI, aritmética sem `checked_`, `init_if_needed`, fechamento/saque manual de lamports, dependência de tempo (TGE/vesting) e `Cargo.toml` sem `overflow-checks`. São indicadores para auditoria manual, não vulnerabilidades confirmadas.
- Análise passiva de **feed JSON de odds** (`python -m vuln_agent feed` ou a aba "Feed JSON" do painel): extrai, offline, os domínios de terceiros referenciados, URLs ocultas em base64 (`broadcastUrl`), proxies com URL embutida no caminho (possível open redirect/SSRF), chaves de embed compartilhadas e a margem (overround) por mercado. Um feed público não é, por si só, vulnerabilidade — os itens são indicadores para revisão.
- Verificação web passiva: HTTPS e certificado TLS, cabeçalhos de segurança (incluindo CSP permissiva e HSTS fraco), proteção contra enquadramento, CORS (curinga, reflexão de origem e `null` com credenciais), divulgação de tecnologia e atributos de cookies. Não explora falhas, não faz fuzzing e não tenta autenticação.
- Relatórios JSON, Markdown e **SARIF 2.1.0** (aba Security do GitHub), ordenados por severidade e com triagem por política.
- Integração opcional com OpenAI API para explicar achados existentes; a IA não executa testes nem inventa evidências.
- GitHub Actions com testes, Semgrep e OSV-Scanner em pull requests/pushes.

## Segurança do próprio VulnAgent
Uma ferramenta de segurança também é superfície de ataque. Proteções incluídas:
- **SSRF / DNS rebinding:** o scanner web resolve o domínio no momento da conexão, recusa qualquer IP não público (loopback, redes privadas, link-local/metadados de nuvem, IPv4 mapeado em IPv6, NAT64) e conecta exatamente no IP validado. Proxies e `.netrc` do ambiente são ignorados.
- **ZIP:** bloqueio de path traversal, limite de entradas e de tamanho descompactado (zip bomb), symlinks ignorados e ZIP com senha recusado.
- **Arquivos locais:** symlinks não são seguidos; `VULNAGENT_ALLOWED_ROOTS` restringe as pastas analisáveis e `VULNAGENT_DISABLE_LOCAL_PATH=1` remove a opção “Pasta local”, o que é necessário ao expor o painel em rede.
- **Relatórios:** evidências não conseguem sair do bloco de código no Markdown e textos externos não injetam links, imagens ou HTML.
- **IA:** instruções vão no canal de sistema, os achados vão como dados JSON com segredos mascarados, e a resposta é higienizada (sem imagens nem links clicáveis), bloqueando exfiltração por prompt injection vinda do código analisado.
- **Semgrep** roda com `--metrics=off`; o painel não envia telemetria do Streamlit (`.streamlit/config.toml`).

## Requisitos
- Windows 10/11, Python 3.11 ou 3.12.
- Git (opcional, para clonar/versionar).
- Semgrep e OSV-Scanner são opcionais no modo local; sem eles, o painel continua funcionando com verificações básicas.

## Instalação no Windows PowerShell
```powershell
# 1. Descompacte o projeto e entre na pasta
cd vuln-agent

# 2. Crie o ambiente virtual
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Se o PowerShell bloquear a ativação, nesta sessão execute:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
# .\.venv\Scripts\Activate.ps1

# 3. Instale dependências
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Copie as configurações de exemplo
Copy-Item .env.example .env

# 5. Inicie o painel
streamlit run app.py
```
Abra o endereço local mostrado pelo Streamlit (normalmente http://localhost:8501).

## Scanners opcionais
### Semgrep
Instale seguindo a documentação oficial: https://semgrep.dev/docs/getting-started/
Depois, confirme:
```powershell
semgrep --version
```
O painel executa regras de segurança `p/default` em modo JSON e com limite de tempo.

### OSV-Scanner
Instale seguindo: https://google.github.io/osv-scanner/
Confirme:
```powershell
osv-scanner --version
```
A execução é feita apenas sobre a pasta de código selecionada.

## Linha de comando (CLI)
A mesma análise do painel, para scripts e CI:
```powershell
python -m vuln_agent code C:\projetos\meu-app                     # relatório Markdown na tela
python -m vuln_agent code codigo.zip -f json -o relatorio.json
python -m vuln_agent code . -f sarif -o vulnagent.sarif --fail-on high
python -m vuln_agent site https://meu-dominio.example -f json
```
`--fail-on` (`critical`, `high`, `medium`, `low`, `info`) retorna código 1 quando há achado com aquela severidade ou maior que não tenha sido triado como “não reportável como está”. Erros de entrada retornam código 2.

Para ver os achados na aba **Security → Code scanning** do GitHub, envie o SARIF com `github/codeql-action/upload-sarif` (requer permissão `security-events: write`; em repositórios privados, GitHub Advanced Security).

## Configurações (`.env`)
| Variável | Função |
| --- | --- |
| `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_TIMEOUT` | IA opcional |
| `HTTP_TIMEOUT` | Timeout da verificação web (1–60 s) |
| `VULNAGENT_SEMGREP_CONFIG` | Pack do Semgrep (padrão `p/default`) ou arquivo de regras local para uso offline |
| `VULNAGENT_ALLOWED_ROOTS` | Pastas permitidas em “Pasta local” (separadas por `;` no Windows, `:` no Linux/macOS) |
| `VULNAGENT_DISABLE_LOCAL_PATH` | `1` remove a opção “Pasta local” (recomendado em servidor compartilhado) |

## Configurar IA (opcional)
Edite `.env` e configure:
```env
OPENAI_API_KEY=
OPENAI_MODEL=gpt-6
```
A chave não deve ser commitada. O módulo de IA envia somente os achados resumidos (no máximo 100, com evidências truncadas em 500 caracteres e segredos mascarados), nunca o código-fonte completo. Sem chave, a aplicação funciona normalmente sem IA.

## Analisar código
- Escolha “Pasta local” e informe o caminho absoluto para a pasta do repositório, ou
- Escolha “Upload ZIP” e envie um arquivo ZIP de código.
- O app executa verificações básicas próprias, heurísticas JS/TS, heurísticas Solana/Anchor (arquivos `.rs` e `Cargo.toml`) e os scanners instalados.
- Faça revisão humana antes de tratar qualquer resultado como vulnerabilidade confirmada.

### Auditar programas Solana/Anchor
Aponte a análise para o repositório do programa (código-fonte, `Cargo.toml`, testes) que você tem autorização para auditar — nunca é feita qualquer interação com a mainnet. As heurísticas cobrem o checklist típico: verificação de signatário/autoridade, substituição de contas, validação de PDA, manipulação de CPI, aritmética, inicialização/encerramento de contas e sequenciamento. Cada achado é apenas um indicador: confirme assinaturas, constraints, PDAs e o impacto concreto antes de reportar, como exige um programa de divulgação responsável.

## Analisar site
- Informe um endereço HTTPS/HTTP de um site sob sua responsabilidade.
- É feita uma única requisição GET para a página inicial, sem seguir redirecionamentos. Ela inclui o cabeçalho `Origin: https://vulnagent-origin-check.invalid` (domínio que não existe) apenas para detectar reflexão de CORS.
- O scanner web é passivo e verifica TLS/HTTPS e cabeçalhos comuns. Não testa SQLi/XSS, não envia payloads e não tenta contornar autenticação.
- Em respostas de redirecionamento, apenas HSTS, cookies e cabeçalhos de identificação são avaliados; analise o destino diretamente se ele estiver no escopo.
- Proxies HTTP definidos no ambiente não são usados (eles impediriam a verificação de IP contra SSRF).
- Não use alvos de terceiros sem autorização expressa.

## GitHub Actions
O workflow `.github/workflows/security.yml` executa os testes (Python 3.11 e 3.12), Semgrep e OSV-Scanner em push e pull request. As actions são fixadas por SHA de commit e o Dependabot (`.github/dependabot.yml`) as mantém atualizadas.

Para rodar os testes localmente:
```powershell
pip install -r requirements-dev.txt
python -m pytest
```
1. Crie um repositório GitHub vazio.
2. Envie os arquivos deste projeto para ele.
3. Em `Settings → Actions → General`, permita os workflows necessários conforme a política da organização.
4. Abra a aba `Actions` para consultar os resultados.
Não coloque tokens pessoais ou chaves de API em arquivos versionados. Para automações que precisem de credenciais, use GitHub Secrets.

## Limitações do MVP
- Não é uma auditoria completa nem certifica ausência de vulnerabilidades.
- Verificações heurísticas podem gerar falsos positivos/negativos; mensagens com `targetOrigin: "*"` podem ser legítimas se não transportarem dados sensíveis.
- Uploads ZIP são extraídos com proteção contra path traversal, zip bomb e symlinks; ainda assim, use arquivos confiáveis.
- As regras próprias são heurísticas de texto: um padrão dentro de string ou comentário (por exemplo, a palavra `eval()` em uma mensagem) também é sinalizado.
- A análise local não envia seu repositório para serviços externos, exceto se você habilitar ferramentas que se conectem a serviços próprios ou configurar IA (que recebe apenas resumos).
