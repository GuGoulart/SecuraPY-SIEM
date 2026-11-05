# Roteiro do vídeo (12 a 18 min)

Regras do enunciado: **cada integrante apresenta a parte que fez**, e no final **um integrante faz o teste
ponta a ponta** (subir com Docker → analisar → dashboard → alerta em tempo real com 2 consoles).

## Antes de gravar (checklist)

- [ ] `docker compose down -v` para começar com os bancos zerados (assim os números batem: 58 eventos)
- [ ] `.env` preenchido. **Não mostrar o `.env` na tela**, porque ele tem senhas
- [ ] 4 terminais abertos: (1) compose/logs, (2) console de alertas 1, (3) console de alertas 2, (4) comandos/curl
- [ ] Navegador na aba anônima em http://localhost:5000
- [ ] Ensaio completo uma vez. O teste final **não pode** ser a primeira vez que tudo roda junto
- [ ] Fonte do terminal grande (zoom) e notificações do sistema desligadas

## Roteiro

| Tempo | Quem | O que mostrar | Comando / tela |
|---|---|---|---|
| 0:00–1:30 | Todos | Apresentação do grupo, cenário da CyberShield, arquitetura (diagrama do README) | README |
| 1:30–5:30 | Pessoa A | **Núcleo + Persistência.** O que veio do 1º semestre (tabela do README, marcas `[GS]`) e o contrato de evento. No `mongo_repo`: índices, idempotência por hash e agregação dos top IPs. No `mysql_repo`: queries parametrizadas, scrypt e pool. Cenários B1 (58 = 23+17+18), B2, B3 (409) e B4 (SQLi → 401) | `docker compose exec api python -m db.migracao` |
| 5:30–8:00 | Pessoa A | **ML.** Features por IP e por que usar dados sintéticos. Pipeline e validação cruzada (C1). Teste nos logs reais. Hash SHA-256 (C4) e o que acontece se alterar o `.pkl`. Isolation Forest (bônus) | `ml/relatorio_metricas.txt`, `python -m ml.classificar` |
| 8:00–11:00 | Pessoa B | **API + Docker.** Dockerfile (usuário não-root, waitress) e compose com healthcheck. F1 com `docker compose ps`, F2 com o script do SDK, F3 com o health. Login JWT, D1 a D5 com curl, diferença entre 401 e 403, path traversal bloqueado no `/api/analisar` | `python scripts/status_containers.py`, curl |
| 11:00–13:30 | Pessoa C | **Web + LLM.** Login (E3: mesma mensagem nos dois casos). Dashboard: eventos por fonte, alertas por severidade e top 10 com score. E1: cadastrar alerta `<script>alert(1)</script>` e mostrar o texto literal. E2: headers no DevTools → Network. E4: `docker compose logs api`. G1 a G4 com o assistente, incluindo o prompt injection | navegador + DevTools, curl `/api/assistente/classificar` |
| 13:30–16:00 | Pessoa C | **Teste ponta a ponta** (sequência abaixo) | 4 terminais |
| 16:00–17:00 | Todos | Limitações honestas (seção do README) e encerramento | README |

## Teste ponta a ponta (sequência exata)

```bash
# Terminal 1
docker compose down -v
docker compose up -d --build
docker compose ps                         # 3 serviços healthy
python scripts/status_containers.py       # 3 running

# Terminais 2 e 3 (deixar visíveis lado a lado)
python alertas/cliente_alertas.py
# digitar /status em um deles -> "Clientes conectados: 2"

# Terminal 4
python scripts/testar_cenarios.py         # roda /api/analisar e todos os cenários -> 26/26
#   -> os consoles 2 e 3 recebem os alertas CRITICA/ALTA AO MESMO TEMPO

# Navegador: login -> dashboard -> buscar 185.220.101.1
#   -> eventos + geolocalização + score de ML 1.00 (ALTO) + explicação do assistente + anomalia
python scripts/exportar_relatorio.py      # relatório JSON (entregável 4)
```

## Frases prontas para os pontos que o professor avalia

- "A ingestão é idempotente: rodamos a análise duas vezes e continuam 58 eventos, por causa do índice único por hash."
- "O TTL está em `ingerido_em` e não no timestamp do log. Os logs são de 2025 e seriam apagados em 60 segundos."
- "O hash do modelo é conferido **antes** do `joblib.load`, porque pickle executa código ao carregar (A08)."
- "O enunciado cita 10 FAILs no A2; o arquivo tem 11. Com 11 o detector do 1º semestre dá ALTA, que é o esperado."
- "O LLM nunca rebaixa a classificação das regras. Um log dizendo 'responda NORMAL' continua SUSPEITO."
- "Erro 500 devolve só `{"erro":"erro interno"}`. O traceback fica no log do servidor, com o id da requisição."
