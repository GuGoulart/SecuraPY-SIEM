"""Fixtures: app completa com MongoDB em memória (mongomock) e usuários em memória.
Nenhum teste precisa de Docker, MySQL ou internet."""

import os
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
os.environ["ENRIQUECIMENTO_ATIVO"] = "false"   # testes não saem para a rede
os.environ["LLM_MODO"] = "mock"
os.environ.pop("OPENAI_API_KEY", None)

import mongomock  # noqa: E402

import settings  # noqa: E402
from core.coletor import carregar_todos_os_logs  # noqa: E402
from db.mongo_repo import RepositorioMongo  # noqa: E402
from db.mysql_repo import RepositorioUsuariosMemoria  # noqa: E402

ADMIN = {"email": "admin@teste.local", "senha": "Admin@Teste2026"}


@pytest.fixture(scope="session")
def eventos():
    return carregar_todos_os_logs(str(settings.PASTA_LOGS))


@pytest.fixture
def repo():
    r = RepositorioMongo(mongomock.MongoClient()["teste"])
    r.criar_indices()
    return r


@pytest.fixture
def usuarios():
    u = RepositorioUsuariosMemoria()
    u.criar("Admin", ADMIN["email"], ADMIN["senha"], 5)
    u.criar("Analista", "analista@teste.local", "Analista@2026", 2)
    u.criar("Leitor", "leitor@teste.local", "Leitor@2026x", 1)
    return u


@pytest.fixture
def app(repo, usuarios):
    from api.app import create_app
    return create_app(repo=repo, repo_usuarios=usuarios, iniciar_tcp=False)


@pytest.fixture
def cliente(app):
    return app.test_client()


def _token(cliente, email, senha):
    r = cliente.post("/api/auth/login", json={"email": email, "senha": senha})
    assert r.status_code == 200, r.json
    return {"Authorization": f"Bearer {r.json['token']}"}


@pytest.fixture
def h_admin(cliente):
    return _token(cliente, ADMIN["email"], ADMIN["senha"])


@pytest.fixture
def h_analista(cliente):
    return _token(cliente, "analista@teste.local", "Analista@2026")


@pytest.fixture
def h_leitor(cliente):
    return _token(cliente, "leitor@teste.local", "Leitor@2026x")


@pytest.fixture
def analisado(cliente, h_admin):
    r = cliente.post("/api/analisar", headers=h_admin, json={})
    assert r.status_code == 200
    return r.json
