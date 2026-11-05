"""
SecuraPy Platform — ponto de entrada de linha de comando.

    python main.py treinar      treina o modelo de ML (gera modelo.pkl + hash + métricas)
    python main.py migrar       ingestão inicial dos logs no MongoDB
    python main.py api          sobe a API + dashboard + servidor TCP (bancos precisam estar no ar)
    python main.py alertas      abre um console cliente de alertas (TCP, 1º semestre)
    python main.py status       status dos contêineres via Docker SDK

Fluxo de orquestração (Seção 4 da GS) — ver plataforma.PlataformaSecuraPy:
  1. eventos = coletor.carregar_todos_os_logs("logs")                      # 1º sem
  2. alertas = regras.aplicar_regras(eventos, regras.carregar_regras(...))  # 1º sem
  3. ameacas = detector.gerar_resumo_ameacas(...)                           # 1º sem
  4. mongo_repo.salvar_eventos / salvar_alertas                             # Módulo B
  5. ml.classificar.pontuar(...)                                            # Módulo C
  6. API expõe, dashboard exibe, LLM explica, alertas via socket            # D, E, G
"""

import sys


def main(argv):
    comando = argv[1] if len(argv) > 1 else "ajuda"
    if comando == "treinar":
        from ml.treinar import treinar
        treinar()
    elif comando == "migrar":
        from db.migracao import main as migrar
        migrar()
    elif comando == "api":
        from waitress import serve
        from api.app import create_app
        serve(create_app(), host="127.0.0.1", port=5000, threads=8)
    elif comando == "alertas":
        from alertas.cliente_alertas import conectar_servidor
        conectar_servidor(*(argv[2:3] or ["127.0.0.1"]))
    elif comando == "status":
        from scripts.status_containers import main as status
        return status()
    else:
        print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
