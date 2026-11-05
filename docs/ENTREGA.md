# Checklist de entrega da GS

| # | Entregável (enunciado) | Onde está | Status |
|---|---|---|---|
| 1 | Código-fonte com Dockerfile e docker-compose | pasta `securaPy_platform/` | pronto |
| 2 | README (integrantes, arquitetura, execução com Docker, dependências, divisão, reaproveitamento) | `README.md` | **preencher nomes e RMs** |
| 3 | Vídeo de 12 a 18 min pelo Teams | `docs/ROTEIRO_VIDEO.md` | gravar |
| 4 | Relatório JSON de exemplo | `saida/relatorio_exemplo.json` (gerem um novo com `scripts/exportar_relatorio.py`) | pronto |
| 5 | `modelo.pkl` + hash + relatório de métricas | `ml/modelo.pkl`, `ml/modelo.pkl.sha256`, `ml/metricas.json`, `ml/relatorio_metricas.txt` | pronto |

## Antes de enviar

1. Preencher nomes, RMs e a divisão real no `README.md`.
2. Rodar `python -m pytest` (57 testes) e `python scripts/testar_cenarios.py` (26/26) com o compose no ar.
3. Garantir que **não existe `.env`** no zip ou no Git. Só o `.env.example` vai junto.
4. Apagar pastas `.venv/`, `__pycache__/` e `.pytest_cache/` antes de zipar.
5. Se o professor pedir repositório Git: `git init`, `git add .`, `git commit -m "SecuraPy Platform - GS"`
   e push para o GitHub. O `.gitignore` já exclui `.env`. Com push, o GitHub Actions roda os testes (bônus CI).
