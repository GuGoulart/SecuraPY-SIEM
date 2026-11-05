"""
Dashboard web dos analistas (Aula 8).

* Jinja2 escapa TUDO por padrão — nenhum `|safe` neste projeto. Um `|safe`
  mal colocado reabriria o XSS (a descrição de um alerta vem de fora).
* Sem JavaScript/CSS inline: a CSP `default-src 'self'` bloquearia (e é bom).
* Login com mensagem genérica, sessão regenerada no login, CSRF nos POSTs.
"""

from functools import wraps

from flask import (Blueprint, current_app, redirect, render_template, request, session, url_for)

from api import seguranca, validacao
from db.mysql_repo import autenticar

web_bp = Blueprint("web", __name__)


def _ext():
    return current_app.extensions["securapy"]


@web_bp.app_context_processor
def _contexto():
    return {"csrf_token": seguranca.token_csrf, "usuario_logado": session.get("email")}


def login_obrigatorio(f):
    @wraps(f)
    def dentro(*args, **kwargs):
        if not session.get("usuario_id"):
            return redirect(url_for("web.login"))
        return f(*args, **kwargs)
    return dentro


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    ext = _ext()
    ip_cliente = request.remote_addr or "-"
    if not seguranca.csrf_valido():
        return render_template("login.html", erro="Sessão expirada. Tente novamente."), 400
    if ext["limitador"].bloqueado(ip_cliente):
        return render_template("login.html", erro="Muitas tentativas. Aguarde alguns minutos."), 429
    email = request.form.get("email", "")[:150]
    senha = request.form.get("senha", "")[:200]
    if not email.strip() or not senha:
        return render_template("login.html", erro="Informe e-mail e senha."), 400
    usuario = autenticar(ext["usuarios"], email, senha)
    if usuario is None:
        ext["limitador"].registrar_falha(ip_cliente)
        # Mesma mensagem para usuário inexistente e senha errada (anti-enumeração, A07)
        return render_template("login.html", erro="Credenciais inválidas."), 401
    ext["limitador"].limpar(ip_cliente)
    session.clear()                     # evita fixação de sessão
    session.permanent = True
    session.update(usuario_id=usuario["id"], email=usuario["email"], nivel=usuario["nivel_acesso"])
    return redirect(url_for("web.dashboard"))


@web_bp.post("/logout")
def logout():
    if seguranca.csrf_valido():
        session.clear()
    return redirect(url_for("web.login"))


@web_bp.get("/")
@login_obrigatorio
def dashboard():
    return render_template("dashboard.html", r=_ext()["plataforma"].resumo_dashboard())


@web_bp.get("/ip")
@login_obrigatorio
def buscar_ip():
    bruto = request.args.get("ip", "").strip()
    if not bruto:
        return redirect(url_for("web.dashboard"))
    try:
        ip = validacao.ip(bruto)
    except validacao.EntradaInvalida:
        return render_template("ip.html", erro="IP inválido.", consulta=bruto), 400
    return render_template("ip.html", p=_ext()["plataforma"].perfil_ip(ip), consulta=ip)


@web_bp.get("/alertas")
@login_obrigatorio
def alertas():
    try:
        pagina, tamanho = validacao.paginacao(request.args)
        filtros = validacao.filtros_alertas(request.args)
    except validacao.EntradaInvalida as erro:
        return render_template("erro.html", status=400, mensagem=str(erro)), 400
    itens, total = _ext()["plataforma"].repo.buscar_alertas(pagina=pagina, tamanho=tamanho, **filtros)
    return render_template("alertas.html", itens=itens, total=total, pagina=pagina, tamanho=tamanho,
                           severidade=filtros.get("severidade", ""))
