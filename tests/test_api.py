"""Módulos D e E — API REST, autenticação, dashboard e segurança web."""

import re

from api.auth import gerar_token


def test_health(cliente):
    r = cliente.get("/api/health")
    assert r.status_code == 200 and r.json["modelo"] == "integro"


def test_analisar(analisado):
    assert analisado["eventos"]["recebidos"] == 58 and analisado["eventos"]["novos"] == 58
    assert analisado["ameacas"][0]["ml"]["risco"] == "ALTO"


def test_d1_alertas_criticos_paginados(cliente, h_admin, analisado):
    r = cliente.get("/api/alertas?severidade=critica&pagina=1&tamanho=5", headers=h_admin)
    assert r.status_code == 200
    assert 0 < len(r.json["itens"]) <= 5 and all(a["severidade"] == "critica" for a in r.json["itens"])


def test_d1_paginacao_e_teto(cliente, h_admin, analisado):
    assert cliente.get("/api/eventos?tamanho=100000", headers=h_admin).json["tamanho"] == 100
    assert cliente.get("/api/eventos?tamanho=abc", headers=h_admin).status_code == 400
    assert cliente.get("/api/eventos?pagina=0", headers=h_admin).status_code == 400
    assert cliente.get("/api/alertas?severidade=urgente", headers=h_admin).status_code == 400


def test_d2_perfil_ip(cliente, h_admin, analisado):
    r = cliente.get("/api/ip/185.220.101.1", headers=h_admin)
    j = r.json
    assert r.status_code == 200 and j["total_eventos"] == 25 and j["alertas"]
    assert j["enriquecimento"] is not None and j["ml"]["risco"] == "ALTO"
    assert j["assistente"]["classificacao"] == "CRITICO"


def test_d3_sem_token_401(cliente):
    assert cliente.post("/api/alertas", json={"tipo": "x", "severidade": "alta", "ip": "1.1.1.1"}).status_code == 401
    assert cliente.get("/api/alertas").status_code == 401
    assert cliente.get("/api/alertas", headers={"Authorization": "Bearer lixo"}).status_code == 401


def test_token_expirado_e_assinatura_errada(cliente, app):
    usuario = {"id": 1, "email": "admin@teste.local", "nivel_acesso": 5}
    expirado = gerar_token(usuario, app.config["JWT_SECRET"], minutos=-1)
    falso = gerar_token(usuario, "segredo-do-atacante", minutos=10)
    for tok in (expirado, falso):
        assert cliente.get("/api/alertas", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_d4_corpo_invalido_400(cliente, h_admin):
    for corpo in ({}, {"severidade": "alta"}, {"tipo": "x", "severidade": "zzz", "ip": "1.1.1.1"},
                  {"tipo": "x", "severidade": "alta", "ip": "999.1.1.1"}):
        assert cliente.post("/api/alertas", headers=h_admin, json=corpo).status_code == 400
    r = cliente.post("/api/alertas", headers=h_admin, data="{quebrado", content_type="application/json")
    assert r.status_code == 400


def test_d5_ip_malformado_400(cliente, h_admin):
    r = cliente.get("/api/ip/999.999.1.1", headers=h_admin)
    assert r.status_code == 400 and r.json == {"erro": "IP inválido"}


def test_alerta_id(cliente, h_admin):
    r = cliente.post("/api/alertas", headers=h_admin, json={"tipo": "Manual", "severidade": "baixa", "ip": "8.8.8.8"})
    assert r.status_code == 201
    assert cliente.get(f"/api/alertas/{r.json['_id']}", headers=h_admin).status_code == 200
    assert cliente.get("/api/alertas/xyz", headers=h_admin).status_code == 400
    assert cliente.get("/api/alertas/" + "a" * 24, headers=h_admin).status_code == 404


def test_403_nivel_insuficiente(cliente, h_leitor, h_analista):
    corpo = {"tipo": "x", "severidade": "alta", "ip": "1.1.1.1"}
    assert cliente.post("/api/alertas", headers=h_leitor, json=corpo).status_code == 403
    assert cliente.post("/api/alertas", headers=h_analista, json=corpo).status_code == 201
    assert cliente.post("/api/analisar", headers=h_analista, json={}).status_code == 403
    assert cliente.get("/api/usuarios", headers=h_analista).status_code == 403


def test_analisar_bloqueia_path_traversal(cliente, h_admin):
    for nome in ("../../etc/passwd", "/etc/passwd", "..\\settings.py", "auth.log/../../x.log"):
        assert cliente.post("/api/analisar", headers=h_admin, json={"arquivo": nome}).status_code == 400
    assert cliente.post("/api/analisar", headers=h_admin, json={"arquivo": "nao_existe.log"}).status_code == 404


def test_analisar_lote_valida(cliente, h_admin):
    ok = {"fonte": "web", "tipo": "GET", "timestamp": "2025-02-21 10:00:00", "ip": "8.8.4.4",
          "detalhes": "url=/../../etc/passwd status=400"}
    r = cliente.post("/api/analisar", headers=h_admin, json={"eventos": [ok]})
    assert r.status_code == 200 and r.json["alertas"]["por_severidade"] == {"critica": 1}
    ruim = dict(ok, fonte="dns")
    assert cliente.post("/api/analisar", headers=h_admin, json={"eventos": [ruim]}).status_code == 400


def test_usuarios_crud(cliente, h_admin):
    r = cliente.post("/api/usuarios", headers=h_admin,
                     json={"nome": "Nova", "email": "nova@teste.local", "senha": "Nova@Senha1", "nivel_acesso": 3})
    assert r.status_code == 201 and "senha_hash" not in r.json
    uid = r.json["id"]
    dup = cliente.post("/api/usuarios", headers=h_admin,
                       json={"nome": "Dup", "email": "nova@teste.local", "senha": "Nova@Senha1"})
    assert dup.status_code == 409
    assert cliente.patch(f"/api/usuarios/{uid}", headers=h_admin, json={"nivel_acesso": 9}).status_code == 400
    assert cliente.patch(f"/api/usuarios/{uid}", headers=h_admin, json={"nivel_acesso": 4}).status_code == 200
    assert cliente.delete(f"/api/usuarios/{uid}", headers=h_admin).status_code == 200
    assert cliente.delete("/api/usuarios/1", headers=h_admin).status_code == 403   # não remove a si mesmo


def test_erro_500_nao_vaza(cliente, h_admin, app, monkeypatch):
    plataforma = app.extensions["securapy"]["plataforma"]

    def explode():
        raise RuntimeError("SELECT * FROM segredo WHERE senha='x' /home/app/settings.py")

    monkeypatch.setattr(plataforma, "resumo_dashboard", explode)
    r = cliente.get("/api/resumo", headers=h_admin)
    assert r.status_code == 500 and r.json == {"erro": "erro interno"}
    assert b"SELECT" not in r.data and b"Traceback" not in r.data


def test_banco_fora_do_ar_503(cliente, h_admin, app, monkeypatch):
    from pymongo.errors import ServerSelectionTimeoutError
    repo = app.extensions["securapy"]["plataforma"].repo

    def fora(*a, **k):
        raise ServerSelectionTimeoutError("mongo:27017 timeout")

    monkeypatch.setattr(repo, "buscar_alertas", fora)
    r = cliente.get("/api/alertas", headers=h_admin)
    assert r.status_code == 503 and r.json == {"erro": "serviço indisponível"}


# ------------------------------------------------------------------ Módulo E
def test_e2_headers(cliente):
    h = cliente.get("/api/health").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in h["Content-Security-Policy"]
    h = cliente.get("/login").headers
    assert "Content-Security-Policy" in h


def test_e3_login_generico(cliente):
    r1 = cliente.post("/api/auth/login", json={"email": "naoexiste@teste.local", "senha": "qualquer"})
    r2 = cliente.post("/api/auth/login", json={"email": "admin@teste.local", "senha": "errada"})
    assert r1.status_code == r2.status_code == 401 and r1.json == r2.json
    assert cliente.post("/api/auth/login", json={"email": "", "senha": ""}).status_code == 400


def test_rate_limit_login(cliente):
    for _ in range(10):
        cliente.post("/api/auth/login", json={"email": "admin@teste.local", "senha": "errada"})
    assert cliente.post("/api/auth/login", json={"email": "admin@teste.local", "senha": "errada"}).status_code == 429


def _login_web(cliente, email="admin@teste.local", senha="Admin@Teste2026"):
    html = cliente.get("/login").get_data(as_text=True)
    csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    return cliente.post("/login", data={"csrf": csrf, "email": email, "senha": senha})


def test_e1_xss_escapado(cliente, h_admin, analisado):
    for payload in ("<script>alert(1)</script>", 'x" onerror="alert(2)'):
        cliente.post("/api/alertas", headers=h_admin,
                     json={"tipo": "XSS", "severidade": "media", "ip": "10.0.0.9", "descricao": payload})
    assert _login_web(cliente).status_code == 302
    html = cliente.get("/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'onerror="alert(2)' not in html          # não escapa do atributo title


def test_e3_login_web_generico(cliente):
    r1 = _login_web(cliente, "naoexiste@teste.local", "x")
    r2 = _login_web(cliente, "admin@teste.local", "errada")
    assert r1.status_code == r2.status_code == 401
    assert "Credenciais inválidas." in r1.get_data(as_text=True) and "Credenciais inválidas." in r2.get_data(as_text=True)


def test_login_web_sem_csrf(cliente):
    r = cliente.post("/login", data={"email": "admin@teste.local", "senha": "Admin@Teste2026"})
    assert r.status_code == 400


def test_dashboard_exige_login(cliente):
    assert cliente.get("/").status_code == 302


def test_e4_logging(cliente, caplog):
    import logging
    with caplog.at_level(logging.INFO, logger="securapy.acesso"):
        cliente.get("/api/health")
        cliente.get("/rota-inexistente")
    linhas = [r.getMessage() for r in caplog.records if r.name == "securapy.acesso"]
    assert any("rota=/api/health" in l and "status=200" in l for l in linhas)
    assert any("rota=/rota-inexistente" in l and "status=404" in l for l in linhas)
