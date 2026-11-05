"""
Autenticação por token (Aula 10) — JWT completo (bônus): geração e verificação.

    Authorization: Bearer <token>

Decorators (patterns, Aula 4) com @wraps. ORDEM nas rotas:
    @bp.post("/rota")          <- SEMPRE o mais de cima (registra a versão protegida)
    @token_obrigatorio
    @requer_nivel(3)
"""

from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

ALGORITMO = "HS256"   # fixo: nunca aceitar o "alg" que vem no token (ataque alg=none)


def gerar_token(usuario, segredo, minutos=60):
    agora = datetime.now(timezone.utc)
    payload = {
        "sub": str(usuario["id"]),
        "email": usuario["email"],
        "nivel": int(usuario["nivel_acesso"]),
        "iat": agora,
        "exp": agora + timedelta(minutes=minutos),
        "iss": "securapy",
    }
    return jwt.encode(payload, segredo, algorithm=ALGORITMO)


def verificar_token(token, segredo):
    """Retorna o payload ou None (expirado, assinatura inválida, malformado...)."""
    try:
        return jwt.decode(token, segredo, algorithms=[ALGORITMO], issuer="securapy",
                          options={"require": ["exp", "sub", "iss"]})
    except jwt.PyJWTError:
        return None


def _nao_autenticado():
    resp = jsonify({"erro": "não autenticado"})
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = 'Bearer realm="securapy"'
    return resp


def token_obrigatorio(f):
    """401 = "não sei quem você é" (sem header, token inválido ou expirado)."""
    @wraps(f)
    def dentro(*args, **kwargs):
        cabecalho = request.headers.get("Authorization", "")
        tipo, _, token = cabecalho.partition(" ")
        if tipo.lower() != "bearer" or not token.strip():
            return _nao_autenticado()
        payload = verificar_token(token.strip(), current_app.config["JWT_SECRET"])
        if payload is None:
            return _nao_autenticado()
        g.usuario = {"id": int(payload["sub"]), "email": payload.get("email"), "nivel": payload.get("nivel", 1)}
        return f(*args, **kwargs)
    return dentro


def requer_nivel(minimo):
    """403 = "sei quem você é e você não pode". Precisa vir ABAIXO de @token_obrigatorio."""
    def decorador(f):
        @wraps(f)
        def dentro(*args, **kwargs):
            usuario = getattr(g, "usuario", None)
            if usuario is None:
                return _nao_autenticado()          # defesa extra se a ordem for invertida
            if usuario["nivel"] < minimo:
                return jsonify({"erro": "acesso negado"}), 403
            return f(*args, **kwargs)
        return dentro
    return decorador
