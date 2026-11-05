"""
API REST da SecuraPy Platform (Aulas 6, 7 e 10) + fábrica da aplicação.

Execução:
    produção/Docker : waitress-serve --host=0.0.0.0 --port=5000 --call api.app:create_app
    local           : python -m api.app

Todas as rotas /api/* (menos /api/health e /api/auth/login) exigem
`Authorization: Bearer <token>`. As de escrita também exigem nível de acesso.
"""

import json
import logging
import secrets
import time

from flask import Blueprint, Flask, current_app, g, jsonify, request

import settings
from alertas.central import CentralDeAlertas, observador_log, observador_tcp
from api import seguranca, validacao
from api.auth import gerar_token, requer_nivel, token_obrigatorio
from api.validacao import EntradaInvalida
from core.contrato import para_json
from db.mysql_repo import (BancoIndisponivel, EmailDuplicado, autenticar, garantir_admin, validar_nivel)
from ia.assistente import classificar_evento
from ml.classificar import ModeloAdulterado, carregar_modelo, verificar_integridade
from plataforma import ArquivoInvalido, PlataformaSecuraPy

log = logging.getLogger("securapy.app")
api_bp = Blueprint("api", __name__, url_prefix="/api")


def _ext():
    return current_app.extensions["securapy"]


def _corpo_json():
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        raise EntradaInvalida("corpo JSON obrigatório")
    return dados


@api_bp.errorhandler(EntradaInvalida)
def _entrada_invalida(erro):
    return jsonify({"erro": str(erro)}), 400


# ====================================================================== públicas
@api_bp.get("/health")
def health():
    ext = _ext()
    estado = {"api": "ok", "mongo": "ok", "mysql": "ok", "modelo": ext["modelo_status"]}
    try:
        ext["plataforma"].repo.db.client.admin.command("ping")
    except Exception:
        estado["mongo"] = "indisponivel"
    try:
        ext["usuarios"].buscar_por_id(0)
    except Exception:
        estado["mysql"] = "indisponivel"
    ok = estado["mongo"] == "ok" and estado["mysql"] == "ok"
    return jsonify(estado), (200 if ok else 503)


@api_bp.post("/auth/login")
def login():
    ext = _ext()
    ip_cliente = request.remote_addr or "-"
    if ext["limitador"].bloqueado(ip_cliente):
        return jsonify({"erro": "muitas tentativas; aguarde alguns minutos"}), 429
    dados = _corpo_json()
    email, senha = dados.get("email"), dados.get("senha")
    if not isinstance(email, str) or not isinstance(senha, str) or not email.strip() or not senha:
        raise EntradaInvalida("campos 'email' e 'senha' obrigatórios")
    usuario = autenticar(ext["usuarios"], email[:150], senha[:200])
    if usuario is None:
        ext["limitador"].registrar_falha(ip_cliente)
        log.warning("login falhou ip=%s", ip_cliente)  # A09: tentativa registrada (sem a senha)
        return jsonify({"erro": "credenciais inválidas"}), 401   # MESMA msg p/ usuário inexistente
    ext["limitador"].limpar(ip_cliente)
    token = gerar_token(usuario, current_app.config["JWT_SECRET"], settings.JWT_EXPIRA_MIN)
    return jsonify({"token": token, "tipo": "Bearer", "expira_em_min": settings.JWT_EXPIRA_MIN,
                    "usuario": para_json(usuario)})


# ====================================================================== eventos/alertas
@api_bp.get("/eventos")
@token_obrigatorio
def listar_eventos():
    pagina, tamanho = validacao.paginacao(request.args)
    filtros = validacao.filtros_eventos(request.args)
    itens, total = _ext()["plataforma"].repo.buscar_eventos(pagina=pagina, tamanho=tamanho, **filtros)
    return jsonify({"pagina": pagina, "tamanho": tamanho, "total": total, "itens": para_json(itens)})


@api_bp.get("/alertas")
@token_obrigatorio
def listar_alertas():
    pagina, tamanho = validacao.paginacao(request.args)
    filtros = validacao.filtros_alertas(request.args)
    itens, total = _ext()["plataforma"].repo.buscar_alertas(pagina=pagina, tamanho=tamanho, **filtros)
    return jsonify({"pagina": pagina, "tamanho": tamanho, "total": total, "itens": para_json(itens)})


@api_bp.get("/alertas/<alerta_id>")
@token_obrigatorio
def obter_alerta(alerta_id):
    try:
        alerta = _ext()["plataforma"].repo.obter_alerta(alerta_id)
    except ValueError:
        return jsonify({"erro": "id inválido"}), 400
    if alerta is None:
        return jsonify({"erro": "alerta não encontrado"}), 404
    return jsonify(para_json(alerta))


@api_bp.post("/alertas")
@token_obrigatorio
@requer_nivel(2)
def criar_alerta():
    alerta = validacao.corpo_alerta(_corpo_json())
    doc = _ext()["plataforma"].repo.criar_alerta(alerta)
    _ext()["central"].publicar(doc)
    return jsonify(para_json(doc)), 201


@api_bp.post("/analisar")
@token_obrigatorio
@requer_nivel(3)
def analisar():
    """Corpo: {} (todos os logs) | {"arquivo": "auth.log"} | {"eventos": [...]}"""
    dados = request.get_json(silent=True)
    if dados is None and request.content_length:
        raise EntradaInvalida("corpo JSON inválido")
    dados = dados or {}
    if not isinstance(dados, dict):
        raise EntradaInvalida("corpo deve ser um objeto JSON")
    plataforma = _ext()["plataforma"]
    if "eventos" in dados:
        resumo = plataforma.analisar_eventos(validacao.lote_eventos(dados["eventos"]))
    elif "arquivo" in dados:
        try:
            resumo = plataforma.analisar_arquivo(dados["arquivo"])
        except ArquivoInvalido as erro:
            raise EntradaInvalida(str(erro))
        except FileNotFoundError:
            return jsonify({"erro": "arquivo de log não encontrado"}), 404
    else:
        resumo = plataforma.analisar_pasta()
    if resumo["eventos"]["recebidos"] == 0:
        return jsonify({"erro": "nenhum evento válido encontrado", **resumo}), 422
    return jsonify(resumo)


@api_bp.get("/ip/<valor>")
@token_obrigatorio
def perfil_ip(valor):
    ip = validacao.ip(valor)  # malformado -> 400 amigável
    enriquecer = request.args.get("enriquecer", "true").lower() != "false"
    return jsonify(_ext()["plataforma"].perfil_ip(ip, enriquecer=enriquecer))


@api_bp.get("/resumo")
@token_obrigatorio
def resumo():
    return jsonify(_ext()["plataforma"].resumo_dashboard())


@api_bp.get("/relatorio")
@token_obrigatorio
def relatorio():
    return jsonify(_ext()["plataforma"].relatorio_completo())


@api_bp.get("/modelo/metricas")
@token_obrigatorio
def metricas_modelo():
    ok, atual, esperado = verificar_integridade(settings.ARQUIVO_MODELO)
    try:
        metricas = json.loads((settings.PASTA_MODELO / "metricas.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        metricas = None
    return jsonify({"integridade": {"ok": ok, "sha256_atual": atual, "sha256_esperado": esperado},
                    "metricas": metricas})


@api_bp.post("/assistente/classificar")
@token_obrigatorio
def assistente():
    evento = _corpo_json().get("evento")
    if not isinstance(evento, (str, dict)) or not evento:
        raise EntradaInvalida("campo 'evento' (texto ou objeto) obrigatório")
    return jsonify(classificar_evento(evento))


# ====================================================================== usuários (nível 5)
@api_bp.get("/usuarios")
@token_obrigatorio
@requer_nivel(5)
def listar_usuarios():
    return jsonify(para_json(_ext()["usuarios"].listar()))


@api_bp.post("/usuarios")
@token_obrigatorio
@requer_nivel(5)
def criar_usuario():
    d = _corpo_json()
    try:
        nivel = d.get("nivel_acesso", 1)
        validar_nivel(nivel)
        uid = _ext()["usuarios"].criar(d.get("nome"), d.get("email"), d.get("senha"), nivel)
    except EmailDuplicado:
        return jsonify({"erro": "email já cadastrado"}), 409
    except ValueError as erro:
        raise EntradaInvalida(str(erro))
    return jsonify(para_json(_ext()["usuarios"].buscar_por_id(uid))), 201


@api_bp.patch("/usuarios/<int:usuario_id>")
@token_obrigatorio
@requer_nivel(5)
def alterar_nivel(usuario_id):
    if usuario_id == g.usuario["id"]:
        return jsonify({"erro": "não é permitido alterar o próprio nível"}), 403
    try:
        ok = _ext()["usuarios"].atualizar_nivel(usuario_id, _corpo_json().get("nivel_acesso"))
    except ValueError as erro:
        raise EntradaInvalida(str(erro))
    if not ok:
        return jsonify({"erro": "usuário não encontrado"}), 404
    return jsonify(para_json(_ext()["usuarios"].buscar_por_id(usuario_id)))


@api_bp.delete("/usuarios/<int:usuario_id>")
@token_obrigatorio
@requer_nivel(5)
def remover_usuario(usuario_id):
    if usuario_id == g.usuario["id"]:
        return jsonify({"erro": "não é permitido remover a si mesmo"}), 403
    if not _ext()["usuarios"].remover(usuario_id):
        return jsonify({"erro": "usuário não encontrado"}), 404
    return jsonify({"mensagem": "removido"})


# ====================================================================== fábrica
def _com_retry(nome, funcao, tentativas=20, espera=3):
    """Os bancos demoram a subir no compose: tenta de novo antes de desistir."""
    for i in range(1, tentativas + 1):
        try:
            return funcao()
        except Exception as erro:
            log.warning("%s indisponível (%s) — tentativa %d/%d", nome, type(erro).__name__, i, tentativas)
            if i == tentativas:
                raise BancoIndisponivel(nome) from erro
            time.sleep(espera)


def _segredo(nome):
    valor = getattr(settings, nome)
    if not valor:
        log.warning("%s não definido — gerando um aleatório (tokens/sessões não sobrevivem a restart)", nome)
        valor = secrets.token_urlsafe(48)
    return valor


def create_app(repo=None, repo_usuarios=None, modelo="carregar", iniciar_tcp=None):
    """Fábrica com injeção de dependência: os testes passam repositórios em memória."""
    from web.views import web_bp

    seguranca.configurar_logging(settings.ARQUIVO_LOG_ACESSO)
    app = Flask(__name__, template_folder=str(settings.RAIZ / "web" / "templates"),
                static_folder=str(settings.RAIZ / "web" / "static"))
    app.config.update(
        SECRET_KEY=_segredo("SECRET_KEY"),
        JWT_SECRET=_segredo("JWT_SECRET"),
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.COOKIE_SEGURO,
        PERMANENT_SESSION_LIFETIME=60 * 60,
    )
    app.json.ensure_ascii = False
    app.json.sort_keys = False

    if repo is None:
        from db.mongo_repo import RepositorioMongo, conectar
        repo = RepositorioMongo(_com_retry("MongoDB", conectar))
    repo.criar_indices()

    if repo_usuarios is None:
        from db.mysql_repo import RepositorioUsuariosMySQL
        repo_usuarios = _com_retry("MySQL", RepositorioUsuariosMySQL)
    _com_retry("MySQL (tabela)", repo_usuarios.criar_tabela)
    if garantir_admin(repo_usuarios, settings.ADMIN_NOME, settings.ADMIN_EMAIL, settings.ADMIN_SENHA):
        log.info("admin inicial criado: %s", settings.ADMIN_EMAIL)

    modelo_status = "nao_carregado"
    if modelo == "carregar":
        try:
            modelo = carregar_modelo(settings.ARQUIVO_MODELO)
            modelo_status = "integro"
        except ModeloAdulterado as erro:
            log.critical(str(erro))
            modelo, modelo_status = None, "adulterado"
        except (OSError, Exception) as erro:  # arquivo ausente / versão incompatível
            log.error("modelo indisponível: %s", type(erro).__name__)
            modelo, modelo_status = None, "indisponivel"
    elif modelo is not None:
        modelo_status = "integro"

    central = CentralDeAlertas()
    central.inscrever(observador_log)
    tcp = settings.ALERTAS_TCP_ATIVO if iniciar_tcp is None else iniciar_tcp
    if tcp:
        from alertas.servidor_alertas import iniciar_em_thread
        iniciar_em_thread(porta=settings.ALERTAS_PORTA)
        central.inscrever(observador_tcp(settings.SEVERIDADES_BROADCAST))

    app.extensions["securapy"] = {
        "plataforma": PlataformaSecuraPy(repo, modelo, central),
        "usuarios": repo_usuarios,
        "central": central,
        "modelo_status": modelo_status,
        "limitador": seguranca.LimitadorTentativas(maximo=10, janela_segundos=300),
    }
    app.register_blueprint(api_bp)
    app.register_blueprint(web_bp)
    seguranca.registrar(app)
    return app


if __name__ == "__main__":
    # debug SEMPRE False (Aula 6.2 / A02): o debugger do Werkzeug é execução remota de código
    create_app().run(host="127.0.0.1", port=5000, debug=False)
