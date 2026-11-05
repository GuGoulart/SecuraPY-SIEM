# SecuraPy Platform — SIEM como Plataforma de Segurança

Trabalho Final (GS) de **Coding for Security**, 2º semestre, FIAP. Prof. Fabio Bara.
A CyberShield Ltda. evoluiu o MVP do SecuraPy CLI (1º semestre) para uma plataforma com
banco de dados, API REST, Machine Learning, dashboard web, assistente com LLM e Docker.

## Integrantes

| Nome | RM | Responsabilidade (módulos) |
|------|----|----------------------------|
| _(integrante 1)_ | RM_____ | Pessoa A: Núcleo + Persistência + ML (A, B, C) |
| Gustavo | RM_____ | Pessoa B: API REST + Docker (D, F) |
| _(integrante 3)_ | RM_____ | Pessoa C: Web + LLM + integração final (E, G, compose/integração) |

> Divisão baseada na sugestão do enunciado para equipe de 3 (seção 7). Ajustem nomes, RMs e a divisão antes de entregar. A seção [Divisão de tarefas](#divisão-de-tarefas)
> detalha quais arquivos ficaram com cada integrante.

---

## Arquitetura

```
                    ┌──────────────────────────── docker compose (rede securapy_net) ───────────────────────────┐
 Navegador ───────► │  securapy-api  :5000  (Flask + waitress, 1 processo)                                       │
 curl / scripts ──► │   ├─ api/        REST, JWT, validação, status codes, headers, log de acesso                │
                    │   ├─ web/        dashboard Jinja2 (escape automático, CSP, CSRF, login genérico)            │
 Console TCP ◄───── │   ├─ alertas/    servidor TCP do 1º sem :9999 (broadcast em tempo real, padrão Observer)    │
 (cliente_alertas)  │   ├─ plataforma.py  Facade: núcleo → regras → detector → correlação → ML → persistência     │
                    │   ├─ core/       NÚCLEO DO 1º SEMESTRE (coletor, regras, detector, enriquecimento)          │
                    │   ├─ ml/         Pipeline scikit-learn + joblib + SHA-256, Isolation Forest                 │
                    │   └─ ia/         assistente LLM (OpenAI ou mock) com fallback por regras                    │
                    │         │                               │                                                   │
                    │         ▼                               ▼                                                   │
                    │  securapy-mongo :27017            securapy-mysql :3306                                      │
                    │  eventos, alertas (volume,         usuarios/operadores (UNIQUE, CHECK,                       │
                    │  schema flexível, agregação, TTL)  ACID, queries parametrizadas)                            │
                    └───────────────────────────────────────────────────────────────────────────────────────────┘
```

```
securaPy_platform/
├── core/                 NÚCLEO (1º sem): coletor, regras, detector, enriquecimento, relatorios
│   ├── contrato.py       contrato evento/alerta (a "cola" entre os módulos)
│   ├── correlacao.py     [bônus] brute force em janela de tempo
│   └── blacklist.py      blacklist lida de config/blacklist.txt
├── db/                   mongo_repo.py, mysql_repo.py, migracao.py, init_mysql.sql
├── ml/                   features, treinar, classificar, anomalias, modelo.pkl(+.sha256), metricas.json
├── api/                  app.py (rotas e fábrica), auth.py (JWT), seguranca.py, validacao.py
├── ia/                   assistente.py
├── web/                  views.py, templates/, static/style.css
├── alertas/              servidor_alertas.py, cliente_alertas.py (1º sem) + central.py (Observer)
├── scripts/              testar_cenarios.py, status_containers.py, exportar_relatorio.py, servidor_demo.py
├── tests/                57 testes pytest, sem Docker
├── logs/  config/        dados de teste e regras (os mesmos do 1º sem)
├── saida/                relatorio_exemplo.json (entregável 4)
├── plataforma.py  settings.py  main.py
├── Dockerfile  docker-compose.yml  .env.example
└── requirements.txt  requirements-dev.txt
```

**Design patterns** (apostila extra): *Repository* (`db/`, o único lugar com SQL), *Facade* (`plataforma.py`),
*Observer* (`alertas/central.py`, um canal quebrado não derruba os outros), *Decorator*
(`@token_obrigatorio` e `@requer_nivel` com `@wraps`, na ordem certa), *Adapter* (`core/contrato.py`)
e **pool de conexões em vez de Singleton** (MySQL).

---

## Como executar (Docker, o modo de entrega)

**Pré-requisitos:** Docker Desktop (ou Docker Engine + Compose v2) e Git. Para rodar os scripts no host
(console de alertas, status e cenários), use Python 3.12 ou mais novo.

```bash
# 1. Configurar os segredos (o .env nunca vai para o Git)
cp .env.example .env            # Windows PowerShell: Copy-Item .env.example .env
#    Edite o .env e troque TODAS as senhas e chaves "troque-..."

# 2. Subir API + MongoDB + MySQL
docker compose up -d --build
docker compose ps               # os 3 contêineres devem estar "running (healthy)"

# 3. Conferir que tudo está no ar (Docker SDK)
pip install docker requests
python scripts/status_containers.py

# 4. Ingestão inicial (migração dos 3 logs para o MongoDB)
docker compose exec api python -m db.migracao
```

- Dashboard: <http://localhost:5000>. O login usa `ADMIN_EMAIL` e `ADMIN_SENHA` do `.env`.
- API: <http://localhost:5000/api/health>.
- Alertas em tempo real: abra **dois** terminais e rode em cada um `python alertas/cliente_alertas.py`.
  Depois chame `POST /api/analisar`: os alertas críticos e altos aparecem nos dois consoles.

### Usando a API (curl)

```bash
# Login -> token JWT
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login -H "Content-Type: application/json" \
  -d '{"email":"admin@cybershield.local","senha":"SUA_SENHA_DO_ENV"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -s -X POST http://localhost:5000/api/analisar -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'
curl -s "http://localhost:5000/api/alertas?severidade=critica&pagina=1&tamanho=5" -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:5000/api/ip/185.220.101.1 -H "Authorization: Bearer $TOKEN"
```

No PowerShell:

```powershell
$r = Invoke-RestMethod -Method Post http://localhost:5000/api/auth/login -ContentType "application/json" `
     -Body '{"email":"admin@cybershield.local","senha":"SUA_SENHA_DO_ENV"}'
$H = @{ Authorization = "Bearer $($r.token)" }
Invoke-RestMethod -Method Post http://localhost:5000/api/analisar -Headers $H -ContentType "application/json" -Body '{}'
Invoke-RestMethod "http://localhost:5000/api/ip/185.220.101.1" -Headers $H
```

### Rodar todos os cenários de teste do enunciado

```bash
# Linux/Mac: export ADMIN_EMAIL=... ADMIN_SENHA=...   |   PowerShell: $env:ADMIN_EMAIL="..."; $env:ADMIN_SENHA="..."
python scripts/testar_cenarios.py          # imprime PASSOU/FALHOU de A1 a G4 (26 cenários)
python scripts/exportar_relatorio.py       # gera saida/relatorio_AAAAMMDD_HHMMSS.json
```

### Testes automatizados e modo demo (sem Docker)

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest                     # 57 testes (mongomock + repositório em memória)
python -m scripts.servidor_demo      # plataforma completa com bancos em memória, em http://127.0.0.1:5000
python -m ml.treinar                 # re-treina o modelo (gera modelo.pkl, .sha256 e metricas.json)
```

### Comandos úteis

```bash
docker compose logs -f api                       # log da API e de acesso (A09)
docker compose exec api tail -n 20 var/acesso.log
docker compose down                              # para tudo (mantém os dados)
docker compose down -v                           # para e APAGA os volumes (Mongo e MySQL zerados)
```

---

## API REST

Todas as rotas `/api/*`, exceto `health` e `auth/login`, exigem `Authorization: Bearer <token>`.

| Método | Rota | Nível | Descrição |
|---|---|---|---|
| GET | `/api/health` | público | Estado de API, Mongo, MySQL e integridade do modelo |
| POST | `/api/auth/login` | público | `{"email","senha"}` → JWT. Responde 401 genérico e 429 após 10 falhas em 5 min |
| GET | `/api/eventos` | 1 | Filtros `fonte`, `tipo`, `ip`, `desde`, `ate`; paginação `pagina` e `tamanho` (teto 100) |
| GET | `/api/alertas` | 1 | Filtros `severidade`, `ip`, `origem`; ordenado pelo **score de ML** |
| GET | `/api/alertas/<id>` | 1 | 400 para id malformado, 404 se não existir |
| POST | `/api/alertas` | 2 | `{"tipo","severidade","ip","descricao"}` → 201 |
| POST | `/api/analisar` | 3 | `{}` (todos os logs), `{"arquivo":"auth.log"}` ou `{"eventos":[...]}` |
| GET | `/api/ip/<ip>` | 1 | Eventos, alertas, geolocalização, score de ML, anomalia e explicação do LLM |
| GET | `/api/resumo` | 1 | Dados do dashboard |
| GET | `/api/relatorio` | 1 | Relatório JSON completo |
| GET | `/api/modelo/metricas` | 1 | Precisão, recall, F1, matriz de confusão e hash |
| POST | `/api/assistente/classificar` | 1 | `{"evento": "..."}` → NORMAL / SUSPEITO / CRITICO |
| GET, POST | `/api/usuarios` | 5 | CRUD de operadores (409 para e-mail duplicado) |
| PATCH, DELETE | `/api/usuarios/<id>` | 5 | Alterar nível ou remover (nunca o próprio usuário) |

Códigos de status usados: 200, 201, 400 (entrada inválida), 401 (sem ou com token inválido),
403 (nível insuficiente), 404, 405, 409, 413, 422, 429, 500 (genérico, sem traceback) e 503 (banco fora).

---

## O que foi reaproveitado do 1º semestre

| Arquivo do CP1 | Onde está | O que mudou |
|---|---|---|
| `coletor.py` | `core/` | Só `encoding="utf-8"`, tratamento de arquivo ilegível e ordem determinística (marcado `[GS]`) |
| `regras.py` + `config/regras.json` | `core/` e `config/` | **Sem alteração** |
| `detector.py` | `core/` | Só o import do teste isolado |
| `enriquecimento.py` | `core/` | Usa `ipaddress`, token por variável de ambiente, backoff em 429 e chave para modo offline |
| `relatorios.py` | `core/` | Sem alteração; o CLI antigo continua lá |
| `servidor_alertas.py` / `cliente_alertas.py` | `alertas/` | `iniciar_em_thread()` para rodar junto com a API, porta por env e host/porta por argumento |
| `logs/*.log` | `logs/` | Sem alteração |
| Blacklist do `main.py` | `config/blacklist.txt` | Saiu do código e foi para configuração |

As camadas novas (db, ml, api, web, ia, Docker) **chamam** o núcleo sem reescrevê-lo. O comportamento
de detecção é idêntico ao do 1º semestre.

---

## Decisões e limitações (honestidade técnica)

- **A2 cita 10 FAILs; o `auth.log` tem 11** para `185.220.101.1`. Com 11 falhas o detector classifica
  como ALTA, que é a severidade pedida. Com exatamente 10 o resultado seria MEDIA, porque a regra do
  1º semestre é "mais de 10". Mantivemos o log e o detector originais.
- **Severidade padronizada** em `critica, alta, media, baixa, info` na fronteira da API. O núcleo segue
  emitindo `CRITICA` e similares, como no 1º semestre.
- **ML com poucos dados reais.** Os logs têm só 7 IPs, o que impede validação cruzada de 5 folds.
  Por isso o treino usa 500 amostras sintéticas (`random_state=42`, com 15% de normais "difíceis" e 3%
  de ruído de rótulo). O modelo vencedor do torneio é testado nos **logs reais, que ele nunca viu**.
  A validação cruzada deu F1 de aproximadamente 0,94 (ver `ml/metricas.json`). A acurácia foi omitida
  de propósito, porque engana em dados desbalanceados.
- **Integridade do modelo:** o SHA-256 é verificado **antes** do `joblib.load`, já que um pickle executa
  código ao carregar (A08). Se o modelo for adulterado, a API sobe sem ML e `/api/health` mostra o problema.
- **Senhas de operador** usam scrypt com salt (`werkzeug.security`). SHA-256 puro não serve para senha,
  segundo o OWASP Password Storage Cheat Sheet. Existe também um "hash fantasma" para que o tempo de
  resposta seja igual quando o usuário não existe.
- **TTL** fica em `ingerido_em`, nunca no `timestamp` do log. Os logs são de 2025 e seriam apagados em
  cerca de 60 s.
- **Ingestão idempotente:** existe índice único por SHA-256 da linha, então analisar duas vezes não duplica.
- **`POST /api/analisar` com arquivo** aceita só o nome de um `.log` dentro de `logs/` (anti path traversal).
- **Leituras da API também exigem token.** O enunciado pede token só nas escritas; exigimos nas leituras
  porque expor eventos de segurança sem autenticação seria A01.
- **LLM:** o padrão é o modo mock. Com `OPENAI_API_KEY` no `.env`, o assistente usa `gpt-4o-mini` com
  temperature 0,1, entrada delimitada, saída validada e guarda-corpo: o LLM nunca rebaixa a classificação
  das regras.
- **Servidor TCP de alertas** sem autenticação: é uma herança do 1º semestre e uma limitação conhecida.
  Em produção usaríamos TLS e token.

---

## Mapa dos cenários de teste → evidência

| Cenário | Como comprovar |
|---|---|
| A1–A4, B1–B4, C1–C4, D1–D5, E1–E3, F3, G1–G4 | `python scripts/testar_cenarios.py` (26/26) e `python -m pytest` (57) |
| E4 (logging) | `docker compose logs api` → linhas `securapy.acesso ip=... rota=... status=...` |
| F1 | `docker compose up -d --build` + `docker compose ps` |
| F2 | `python scripts/status_containers.py` |
| C1 | `python -m ml.treinar` (local, com requirements-dev) ou `ml/relatorio_metricas.txt` e `GET /api/modelo/metricas` |

## Divisão de tarefas

| Integrante | Arquivos |
|---|---|
| Pessoa A (Núcleo + Persistência + ML) | `core/*`, `db/*`, `ml/*`, `tests/test_nucleo.py`, `tests/test_persistencia.py`, `tests/test_ml.py` |
| Pessoa B (API + Docker) | `api/*`, `Dockerfile`, `docker-compose.yml`, `.env.example`, `scripts/status_containers.py`, `tests/test_api.py` |
| Pessoa C (Web + LLM + integração) | `web/*`, `ia/assistente.py`, `alertas/central.py`, `plataforma.py`, `scripts/testar_cenarios.py`, `tests/test_assistente.py` |
| Todos | `tests/`, `scripts/testar_cenarios.py`, README, vídeo |

## Dependências

Ver `requirements.txt`, com versões fixas: Flask, waitress, PyMongo, mysql-connector-python,
scikit-learn, numpy, joblib, requests, PyJWT, openai e docker. Para desenvolvimento:
`requirements-dev.txt` (pytest e mongomock).

## Referências

- Apostilas do 1º e 2º semestres e apostila de Design Patterns (Prof. Fabio Bara)
- OWASP Top 10:2025: <https://owasp.org/Top10/>
- OWASP Password Storage Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- Flask: <https://flask.palletsprojects.com/> · PyMongo: <https://pymongo.readthedocs.io/> · MySQL Connector/Python: <https://dev.mysql.com/doc/connector-python/en/>
- scikit-learn (Pipeline, validação cruzada e persistência): <https://scikit-learn.org/stable/>
- Docker SDK for Python: <https://docker-py.readthedocs.io/>
