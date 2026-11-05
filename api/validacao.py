"""Validação de entrada da API — whitelist em tudo que vira filtro de banco."""

import ipaddress
import re

from core.contrato import FONTES, SEVERIDADES, normalizar_severidade, parse_timestamp

TAMANHO_PADRAO, TAMANHO_MAXIMO = 20, 100
TIPO_VALIDO = re.compile(r"^[A-Z]{2,10}$")
ORIGENS = ("regra", "detector", "correlacao", "manual")
MAX_EVENTOS_LOTE = 1000


class EntradaInvalida(ValueError):
    """Mensagem é segura para devolver ao cliente (vira 400)."""


def inteiro(args, nome, padrao, minimo=1, maximo=None):
    bruto = args.get(nome)
    if bruto is None or bruto == "":
        return padrao
    try:
        valor = int(bruto)
    except (TypeError, ValueError):
        raise EntradaInvalida(f"{nome} deve ser inteiro")
    if valor < minimo:
        raise EntradaInvalida(f"{nome} deve ser >= {minimo}")
    return min(valor, maximo) if maximo else valor  # teto do servidor (não erro)


def paginacao(args):
    return inteiro(args, "pagina", 1), inteiro(args, "tamanho", TAMANHO_PADRAO, maximo=TAMANHO_MAXIMO)


def ip(valor):
    try:
        return str(ipaddress.ip_address(str(valor).strip()))
    except ValueError:
        raise EntradaInvalida("IP inválido")


def severidade(valor):
    sev = normalizar_severidade(valor)
    if sev is None:
        raise EntradaInvalida(f"severidade inválida; use: {', '.join(SEVERIDADES)}")
    return sev


def data(valor, nome):
    try:
        return parse_timestamp(valor)
    except (ValueError, TypeError):
        raise EntradaInvalida(f"{nome} deve ser data 'YYYY-MM-DD HH:MM:SS' ou ISO 8601")


def filtros_eventos(args):
    f = {}
    if args.get("fonte"):
        if args["fonte"] not in FONTES:
            raise EntradaInvalida(f"fonte inválida; use: {', '.join(FONTES)}")
        f["fonte"] = args["fonte"]
    if args.get("tipo"):
        tipo = args["tipo"].upper()
        if not TIPO_VALIDO.fullmatch(tipo):
            raise EntradaInvalida("tipo inválido")
        f["tipo"] = tipo
    if args.get("ip"):
        f["ip"] = ip(args["ip"])
    if args.get("desde"):
        f["desde"] = data(args["desde"], "desde")
    if args.get("ate"):
        f["ate"] = data(args["ate"], "ate")
    return f


def filtros_alertas(args):
    f = {}
    if args.get("severidade"):
        f["severidade"] = severidade(args["severidade"])
    if args.get("ip"):
        f["ip"] = ip(args["ip"])
    if args.get("origem"):
        if args["origem"] not in ORIGENS:
            raise EntradaInvalida(f"origem inválida; use: {', '.join(ORIGENS)}")
        f["origem"] = args["origem"]
    return f


def texto(dados, campo, maximo, obrigatorio=True):
    valor = dados.get(campo)
    if valor is None or (isinstance(valor, str) and not valor.strip()):
        if obrigatorio:
            raise EntradaInvalida(f"campo '{campo}' obrigatório")
        return ""
    if not isinstance(valor, str):
        raise EntradaInvalida(f"campo '{campo}' deve ser texto")
    if len(valor) > maximo:
        raise EntradaInvalida(f"campo '{campo}' excede {maximo} caracteres")
    return valor.strip()


def corpo_alerta(dados):
    """POST /api/alertas — só os campos conhecidos (sem mass assignment)."""
    if not isinstance(dados, dict):
        raise EntradaInvalida("corpo JSON obrigatório")
    return {
        "regra": texto(dados, "regra", 100, obrigatorio=False) or texto(dados, "tipo", 100),
        "severidade": severidade(dados.get("severidade")),
        "ip": ip(dados.get("ip", "")),
        "descricao": texto(dados, "descricao", 500, obrigatorio=False),
        "regra_id": "MANUAL",
        "pontuacao": 0,
    }


def lote_eventos(lista):
    """Valida eventos enviados direto no POST /api/analisar."""
    if not isinstance(lista, list) or not lista:
        raise EntradaInvalida("'eventos' deve ser uma lista não vazia")
    if len(lista) > MAX_EVENTOS_LOTE:
        raise EntradaInvalida(f"máximo de {MAX_EVENTOS_LOTE} eventos por lote")
    eventos = []
    for i, e in enumerate(lista):
        if not isinstance(e, dict):
            raise EntradaInvalida(f"evento {i}: deve ser objeto")
        fonte = e.get("fonte")
        if fonte not in FONTES:
            raise EntradaInvalida(f"evento {i}: fonte inválida")
        tipo = str(e.get("tipo", "")).upper()
        if not TIPO_VALIDO.fullmatch(tipo):
            raise EntradaInvalida(f"evento {i}: tipo inválido")
        ts = data(e.get("timestamp", ""), f"evento {i}: timestamp")
        detalhes = e.get("detalhes", "")
        if not isinstance(detalhes, str) or len(detalhes) > 500:
            raise EntradaInvalida(f"evento {i}: detalhes deve ser texto até 500 caracteres")
        ip_ok = ip(e.get("ip", ""))
        eventos.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "fonte": fonte, "tipo": tipo, "ip": ip_ok, "detalhes": detalhes,
            "linha_original": f"{ts:%Y-%m-%d %H:%M:%S} {tipo} {detalhes} ip={ip_ok}",
        })
    return eventos
