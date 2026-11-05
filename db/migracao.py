"""
Migração / ingestão inicial: lê os 3 logs via núcleo do 1º semestre e popula
o MongoDB (eventos + alertas de regras, detector e correlação).

    python -m db.migracao                          (local, com Mongo no ar)
    docker compose exec api python -m db.migracao  (dentro do compose)

Idempotente: rodar de novo não duplica nada (índice único por hash).
"""

import settings
from core.coletor import carregar_todos_os_logs
from db.mongo_repo import RepositorioMongo, conectar
from ml.classificar import ModeloAdulterado, carregar_modelo
from plataforma import PlataformaSecuraPy


def main():
    print(f"Conectando ao MongoDB em {settings.MONGO_HOST}:{settings.MONGO_PORTA} ...")
    repo = RepositorioMongo(conectar())
    repo.criar_indices()
    try:
        modelo = carregar_modelo(settings.ARQUIVO_MODELO)
    except (ModeloAdulterado, OSError) as erro:
        print(f"[AVISO] modelo de ML não carregado ({erro}); seguindo sem score.")
        modelo = None

    eventos = carregar_todos_os_logs(str(settings.PASTA_LOGS))
    resumo = PlataformaSecuraPy(repo, modelo).analisar_eventos(eventos)
    pf = resumo["eventos"]["por_fonte"]
    print(f"\nEventos lidos: {resumo['eventos']['recebidos']} "
          f"({pf.get('auth', 0)} auth + {pf.get('firewall', 0)} firewall + {pf.get('web', 0)} web)")
    print(f"Eventos novos persistidos: {resumo['eventos']['novos']} | total na coleção: {repo.totais()['eventos']}")
    print(f"Alertas gerados: {resumo['alertas']['gerados']} | novos: {resumo['alertas']['novos']}")
    print("\n=== Top 5 IPs por eventos (agregação no MongoDB) ===")
    for item in repo.top_ips(5):
        print(f"{item['ip']:<16} -> {item['eventos']} eventos ({', '.join(item['fontes'])})")
    print("\n=== Alertas por severidade ===")
    for sev, qtd in sorted(repo.contagem_por_severidade().items()):
        print(f"{sev:<8} {qtd}")


if __name__ == "__main__":
    main()
