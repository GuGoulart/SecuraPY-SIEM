"""Módulo B — MongoDB (B1, B2) e MySQL/usuários (B3, B4)."""

import pytest

from db.mysql_repo import EmailDuplicado, RepositorioUsuariosMySQL, autenticar


def test_b1_ingestao_58_eventos_idempotente(repo, eventos):
    assert repo.salvar_eventos(eventos) == 58
    assert repo.salvar_eventos(eventos) == 0          # 2ª vez não duplica
    assert repo.contagem_por_fonte() == {"auth": 23, "firewall": 17, "web": 18}


def test_b2_top_ips(repo, eventos):
    repo.salvar_eventos(eventos)
    top = repo.top_ips(5)
    assert top[0]["ip"] == "185.220.101.1" and top[0]["eventos"] == 25
    assert repo.top_ips_falhas(3)[0] == {"ip": "185.220.101.1", "falhas": 11}


def test_filtros_e_paginacao(repo, eventos):
    repo.salvar_eventos(eventos)
    itens, total = repo.buscar_eventos(pagina=1, tamanho=5, fonte="auth", tipo="FAIL", ip="185.220.101.1")
    assert total == 11 and len(itens) == 5


def test_id_malformado(repo):
    with pytest.raises(ValueError):
        repo.obter_alerta("nao-e-objectid")


def test_b3_email_duplicado(usuarios):
    with pytest.raises(EmailDuplicado):
        usuarios.criar("Outro", "ADMIN@teste.local", "Outra@Senha1", 2)


def test_nivel_fora_da_faixa(usuarios):
    with pytest.raises(ValueError):
        usuarios.criar("X", "x@teste.local", "Senha@forte1", 9)


def test_senha_nunca_em_texto_puro(usuarios):
    reg = usuarios.buscar_para_login("admin@teste.local")
    assert reg["senha_hash"].startswith("scrypt:") and "Admin@Teste2026" not in reg["senha_hash"]
    assert "senha_hash" not in usuarios.buscar_por_email("admin@teste.local")


def test_b4_sqli_no_login_nao_autentica(usuarios):
    assert autenticar(usuarios, "' OR '1'='1", "' OR '1'='1") is None


class CursorEspiao:
    """Captura (sql, parametros) para provar que a entrada NUNCA entra no texto SQL."""
    def __init__(self):
        self.chamadas, self.rowcount, self.lastrowid = [], 0, 1

    def execute(self, sql, params=None):
        self.chamadas.append((sql, params))

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def close(self):
        pass


def test_b4_mysql_repo_usa_query_parametrizada(monkeypatch):
    from contextlib import contextmanager
    repo = RepositorioUsuariosMySQL.__new__(RepositorioUsuariosMySQL)
    espiao = CursorEspiao()

    @contextmanager
    def cursor_fake():
        yield espiao

    monkeypatch.setattr(repo, "_cursor", cursor_fake)
    ataque = "' OR '1'='1"
    repo.buscar_para_login(ataque)
    repo.buscar_por_email(ataque)
    repo.remover(ataque)
    for sql, params in espiao.chamadas:
        assert ataque not in sql and "%s" in sql
        assert ataque.lower() in [str(p).lower() for p in params]
