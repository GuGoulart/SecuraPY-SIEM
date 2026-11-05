"""
Camada transversal de segurança (Aula 8 — OWASP Top 10:2025).

  * Headers de segurança em TODAS as respostas (A02).
  * Log de acesso de cada requisição (A09) — sem senha, token ou corpo.
  * Handlers de erro que nunca vazam traceback, query ou segredo (A10/A02).
  * Limite de tentativas de login por IP (A07).
"""

import logging
import secrets
import threading
import time
import uuid
from logging.handlers import RotatingFileHandler

from flask import g, jsonify, render_template, request, session
from pymongo.errors import PyMongoError
from werkzeug.exceptions import HTTPException

from db.mysql_repo import BancoIndisponivel

log_acesso = logging.getLogger("securapy.acesso")
log_app = logging.getLogger("securapy.app")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


def configurar_logging(caminho_arquivo):
    caminho_arquivo.parent.mkdir(parents=True, exist_ok=True)
    formato = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    raiz = logging.getLogger("securapy")
    if raiz.handlers:
        return
    raiz.setLevel(logging.INFO)
    console = logging.StreamHandler()
    console.setFormatter(formato)
    raiz.addHandler(console)
    try:
        arquivo = RotatingFileHandler(caminho_arquivo, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        arquivo.setFormatter(formato)
        raiz.addHandler(arquivo)
    except OSError:
        raiz.warning("não foi possível abrir %s; log só no console", caminho_arquivo)


def _eh_api():
    return request.path.startswith("/api/")


# ---------------------------------------------------------------- rate limit login
class LimitadorTentativas:
    """Janela fixa em memória por IP: N falhas em X segundos -> 429."""

    def __init__(self, maximo=5, janela_segundos=300):
        self.maximo, self.janela = maximo, janela_segundos
        self._falhas = {}
        self._lock = threading.Lock()

    def _limpar(self, ip, agora):
        self._falhas[ip] = [t for t in self._falhas.get(ip, []) if agora - t < self.janela]

    def bloqueado(self, ip):
        with self._lock:
            self._limpar(ip, time.monotonic())
            return len(self._falhas[ip]) >= self.maximo

    def registrar_falha(self, ip):
        with self._lock:
            agora = time.monotonic()
            self._limpar(ip, agora)
            self._falhas[ip].append(agora)

    def limpar(self, ip):
        with self._lock:
            self._falhas.pop(ip, None)


# ---------------------------------------------------------------- CSRF (formulários web)
def token_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_valido():
    enviado = request.form.get("csrf", "")
    return bool(enviado) and secrets.compare_digest(enviado, session.get("csrf", ""))


# ---------------------------------------------------------------- registro no app
def registrar(app):
    @app.before_request
    def _inicio():
        g.inicio = time.perf_counter()
        g.req_id = uuid.uuid4().hex[:12]

    @app.after_request
    def _headers_e_log(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Request-ID"] = getattr(g, "req_id", "-")
        if _eh_api():
            resp.headers["Cache-Control"] = "no-store"
        duracao = (time.perf_counter() - getattr(g, "inicio", time.perf_counter())) * 1000
        usuario = (getattr(g, "usuario", None) or {}).get("email") or session.get("email") or "-"
        # Nunca registrar Authorization, senha ou corpo; query string limitada e sem quebras de linha
        rota = request.full_path.rstrip("?")[:300].replace("\n", " ").replace("\r", " ")
        log_acesso.info("ip=%s metodo=%s rota=%s status=%s ms=%.1f usuario=%s req=%s",
                        request.remote_addr, request.method, rota, resp.status_code,
                        duracao, usuario, getattr(g, "req_id", "-"))
        return resp

    def _resposta(status, mensagem):
        if _eh_api():
            return jsonify({"erro": mensagem}), status
        return render_template("erro.html", status=status, mensagem=mensagem), status

    @app.errorhandler(HTTPException)
    def _http(erro):
        mensagens = {400: "requisição inválida", 401: "não autenticado", 403: "acesso negado",
                     404: "recurso não encontrado", 405: "método não permitido",
                     413: "corpo da requisição muito grande", 415: "tipo de conteúdo não suportado",
                     429: "muitas requisições"}
        return _resposta(erro.code, mensagens.get(erro.code, "erro na requisição"))

    @app.errorhandler(PyMongoError)
    @app.errorhandler(BancoIndisponivel)
    def _banco(erro):
        log_app.error("banco indisponível: %s (req=%s)", type(erro).__name__, getattr(g, "req_id", "-"))
        return _resposta(503, "serviço indisponível")

    @app.errorhandler(Exception)
    def _interno(erro):
        # traceback completo só no log do servidor; o cliente recebe mensagem genérica
        log_app.exception("erro interno (req=%s)", getattr(g, "req_id", "-"))
        return _resposta(500, "erro interno")
