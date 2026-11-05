"""
Modo DEMO sem Docker e sem bancos instalados (para desenvolvimento rápido).

    pip install -r requirements-dev.txt
    python -m scripts.servidor_demo

Usa mongomock (MongoDB em memória) e o repositório de usuários em memória
(mesma interface do MySQL — padrão Repository). Os dados somem ao fechar.
NÃO é o modo de entrega: a GS roda com `docker compose up`.
"""

import os

os.environ.setdefault("ADMIN_EMAIL", "admin@cybershield.local")
os.environ.setdefault("ADMIN_SENHA", "Admin@Demo2026")

import mongomock  # noqa: E402
from waitress import serve  # noqa: E402

from api.app import create_app  # noqa: E402
from db.mongo_repo import RepositorioMongo  # noqa: E402
from db.mysql_repo import RepositorioUsuariosMemoria  # noqa: E402

if __name__ == "__main__":
    app = create_app(repo=RepositorioMongo(mongomock.MongoClient()["securapy"]),
                     repo_usuarios=RepositorioUsuariosMemoria())
    print("\n=== SecuraPy DEMO (bancos em memória) ===")
    print("Dashboard: http://127.0.0.1:5000  |  Alertas TCP: 127.0.0.1:9999")
    print(f"Login: {os.environ['ADMIN_EMAIL']} / {os.environ['ADMIN_SENHA']}\n")
    serve(app, host="127.0.0.1", port=5000, threads=8)
