# VulnAgent — análise defensiva de código e sites

MVP local com painel Streamlit, integração CI do GitHub Actions e scanners reais opcionais.
**Uso autorizado:** analise somente repositórios e sites que você controla ou para os quais possui autorização expressa.

## Recursos
- Upload de ZIP ou análise de pasta local de código.
- SAST com Semgrep (quando instalado) e verificação de dependências com OSV-Scanner (quando instalado).
- Verificação web passiva: HTTPS, cabeçalhos de segurança e cookies observáveis. Não explora falhas, não faz fuzzing e não tenta autenticação.
- Relatórios JSON e Markdown.
- Integração opcional com OpenAI API para explicar achados existentes; a IA não executa testes nem inventa evidências.
- GitHub Actions para Semgrep e OSV-Scanner em pull requests/pushes.

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

## Configurar IA (opcional)
Edite `.env` e configure:
```env
OPENAI_API_KEY=
OPENAI_MODEL=gpt-6
```
A chave não deve ser commitada. O módulo de IA envia somente os achados resumidos, não o código-fonte. Sem chave, a aplicação funciona normalmente sem IA.

## Analisar código
- Escolha “Pasta local” e informe o caminho absoluto para a pasta do repositório, ou
- Escolha “Upload ZIP” e envie um arquivo ZIP de código.
- O app executa verificações básicas próprias e os scanners instalados.
- Faça revisão humana antes de tratar qualquer resultado como vulnerabilidade confirmada.

## Analisar site
- Informe um endereço HTTPS/HTTP de um site sob sua responsabilidade.
- Por padrão, apenas uma requisição GET para a página inicial, sem seguir redirecionamentos para outro host.
- O scanner web é passivo e verifica TLS/HTTPS e cabeçalhos comuns. Não testa SQLi/XSS, não envia payloads e não tenta contornar autenticação.
- Não use alvos de terceiros sem autorização expressa.

## GitHub Actions
O workflow `.github/workflows/security.yml` executa Semgrep e OSV-Scanner em push e pull request.
1. Crie um repositório GitHub vazio.
2. Envie os arquivos deste projeto para ele.
3. Em `Settings → Actions → General`, permita os workflows necessários conforme a política da organização.
4. Abra a aba `Actions` para consultar os resultados.
Não coloque tokens pessoais ou chaves de API em arquivos versionados. Para automações que precisem de credenciais, use GitHub Secrets.

## Limitações do MVP
- Não é uma auditoria completa nem certifica ausência de vulnerabilidades.
- Verificações heurísticas podem gerar falsos positivos/negativos.
- Uploads ZIP são extraídos com proteção contra path traversal; ainda assim, use arquivos confiáveis.
- A análise local não envia seu repositório para serviços externos, exceto se você habilitar ferramentas que se conectem a serviços próprios ou configurar IA (que recebe apenas resumos).
