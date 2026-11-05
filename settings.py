"""
Configuração central da plataforma — lida SEMPRE de variáveis de ambiente.

Nenhum segredo fica no código (A02/A04). Valores sem default sensível
(senhas, chaves) precisam vir do .env / docker-compose.
"""

import os
from pathlib import Path

RAIZ = Path(__file__).resolve().parent


def _bool(nome, padrao="false"):
    return os.environ.get(nome, padrao).strip().lower() in ("1", "true", "sim", "yes")


def _int(nome, padrao):
    try:
        return int(os.environ.get(nome, padrao))
    except ValueError:
        return int(padrao)


# --- Caminhos -----------------------------------------------------------
PASTA_LOGS = Path(os.environ.get("PASTA_LOGS", RAIZ / "logs")).resolve()
ARQUIVO_REGRAS = Path(os.environ.get("ARQUIVO_REGRAS", RAIZ / "config" / "regras.json"))
ARQUIVO_BLACKLIST = Path(os.environ.get("ARQUIVO_BLACKLIST", RAIZ / "config" / "blacklist.txt"))
PASTA_MODELO = Path(os.environ.get("PASTA_MODELO", RAIZ / "ml"))
ARQUIVO_MODELO = PASTA_MODELO / "modelo.pkl"
PASTA_SAIDA = Path(os.environ.get("PASTA_SAIDA", RAIZ / "saida"))
# Log de acesso fica FORA de logs/ para não ser ingerido pelo coletor
ARQUIVO_LOG_ACESSO = Path(os.environ.get("ARQUIVO_LOG_ACESSO", RAIZ / "var" / "acesso.log"))

# --- MongoDB ------------------------------------------------------------
MONGO_HOST = os.environ.get("MONGO_HOST", "localhost")
MONGO_PORTA = _int("MONGO_PORTA", 27017)
MONGO_USUARIO = os.environ.get("MONGO_USUARIO", "")
MONGO_SENHA = os.environ.get("MONGO_SENHA", "")
MONGO_BANCO = os.environ.get("MONGO_BANCO", "securapy")
RETENCAO_DIAS = _int("RETENCAO_DIAS", 90)  # TTL (sobre a data de ingestão)

# --- MySQL --------------------------------------------------------------
MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORTA = _int("MYSQL_PORTA", 3306)
MYSQL_USUARIO = os.environ.get("MYSQL_USUARIO", "securapy")
MYSQL_SENHA = os.environ.get("MYSQL_SENHA", "")
MYSQL_BANCO = os.environ.get("MYSQL_BANCO", "securapy")

# --- Segurança da API ---------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY", "")          # sessão do dashboard
JWT_SECRET = os.environ.get("JWT_SECRET", "")          # assinatura dos tokens
JWT_EXPIRA_MIN = _int("JWT_EXPIRA_MIN", 60)
ADMIN_NOME = os.environ.get("ADMIN_NOME", "Administrador")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")
ADMIN_SENHA = os.environ.get("ADMIN_SENHA", "")
COOKIE_SEGURO = _bool("COOKIE_SEGURO", "false")        # true atrás de HTTPS

# --- Alertas em tempo real (TCP do 1º semestre) -------------------------
ALERTAS_TCP_ATIVO = _bool("ALERTAS_TCP_ATIVO", "true")
ALERTAS_PORTA = _int("ALERTAS_PORTA", 9999)
SEVERIDADES_BROADCAST = {"critica", "alta"}

# --- LLM ----------------------------------------------------------------
LLM_MODO = os.environ.get("LLM_MODO", "auto")          # auto | mock | openai
LLM_MODELO = os.environ.get("LLM_MODELO", "gpt-4o-mini")
