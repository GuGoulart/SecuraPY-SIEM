"""
Contrato de dados da plataforma (o "cola" entre os módulos — GS, Dica 2).

O núcleo do 1º semestre continua produzindo exatamente os mesmos
dicionários. Este módulo só faz a ponte para a persistência/API:

EVENTO (MongoDB, coleção `eventos`)
    timestamp       datetime   data/hora do log
    fonte           str        auth | firewall | web
    tipo            str        FAIL, OK, BLOCK, ALLOW, GET, POST, ...
    ip              str
    detalhes        str        "usuario=admin" / "proto=TCP dst=... dport=22" / ...
    linha_original  str
    hash            str        SHA-256(fonte|linha_original) -> idempotência
    ingerido_em     datetime   usado pelo índice TTL (NUNCA o timestamp do log)

ALERTA (MongoDB, coleção `alertas`)
    timestamp, regra, regra_id, severidade (critica|alta|media|baixa|info),
    pontuacao, ip, descricao, origem (regra|detector|correlacao|manual),
    deteccoes (lista, opcional), ml (dict, opcional), hash, criado_em
"""

import hashlib
import unicodedata
import uuid
from datetime import datetime, timezone

FORMATO_TS = "%Y-%m-%d %H:%M:%S"
FONTES = ("auth", "firewall", "web")
SEVERIDADES = ("critica", "alta", "media", "baixa", "info")
PESO_SEVERIDADE = {s: i for i, s in enumerate(reversed(SEVERIDADES))}  # info=0 ... critica=4


def agora():
    """datetime UTC "naive" (o PyMongo devolve datas naive em UTC)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalizar_severidade(valor):
    """'CRITICA' / 'Crítica' / ' alta ' -> 'critica' / 'alta'. Inválido -> None."""
    if valor is None:
        return None
    texto = unicodedata.normalize("NFKD", str(valor)).encode("ascii", "ignore").decode()
    texto = texto.strip().lower()
    return texto if texto in SEVERIDADES else None


def parse_timestamp(valor):
    """Aceita datetime ou 'YYYY-MM-DD HH:MM:SS' / ISO 8601. Inválido -> ValueError."""
    if isinstance(valor, datetime):
        return valor
    texto = str(valor).strip()
    try:
        return datetime.strptime(texto, FORMATO_TS)
    except ValueError:
        return datetime.fromisoformat(texto.replace("Z", "+00:00")).replace(tzinfo=None)


def sha256_texto(texto):
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def evento_para_documento(evento):
    """Evento do coletor (1º sem) -> documento do MongoDB."""
    linha = evento.get("linha_original") or (
        f"{evento['timestamp']} {evento['tipo']} {evento['detalhes']} ip={evento['ip']}"
    )
    return {
        "timestamp": parse_timestamp(evento["timestamp"]),
        "fonte": evento["fonte"],
        "tipo": str(evento["tipo"]).upper(),
        "ip": evento["ip"],
        "detalhes": evento.get("detalhes", ""),
        "linha_original": linha,
        "hash": sha256_texto(f"{evento['fonte']}|{linha}"),
        "ingerido_em": agora(),
    }


def documento_para_evento(doc):
    """Documento do MongoDB -> formato do núcleo (timestamp volta a ser str)."""
    ts = doc["timestamp"]
    return {
        "timestamp": ts.strftime(FORMATO_TS) if isinstance(ts, datetime) else str(ts),
        "fonte": doc["fonte"],
        "tipo": doc["tipo"],
        "ip": doc["ip"],
        "detalhes": doc.get("detalhes", ""),
        "linha_original": doc.get("linha_original", ""),
    }


def alerta_para_documento(alerta, origem="regra"):
    """Alerta do motor de regras / detector -> documento do MongoDB."""
    severidade = normalizar_severidade(alerta.get("severidade")) or "info"
    ts = parse_timestamp(alerta["timestamp"]) if alerta.get("timestamp") else agora()
    doc = {
        "timestamp": ts,
        "regra": alerta.get("regra", "Alerta"),
        "regra_id": alerta.get("regra_id", ""),
        "severidade": severidade,
        "pontuacao": alerta.get("pontuacao", 0),
        "ip": alerta.get("ip", ""),
        "descricao": alerta.get("descricao", ""),
        "origem": origem,
        "criado_em": agora(),
    }
    for extra in ("deteccoes", "ml", "detalhes_deteccao"):
        if extra in alerta:
            doc[extra] = alerta[extra]
    if origem == "manual":
        doc["hash"] = uuid.uuid4().hex                       # alertas manuais nunca colidem
    else:
        chave = f"{doc['regra_id']}|{doc['ip']}|{ts.strftime(FORMATO_TS)}|{doc['descricao']}"
        doc["hash"] = sha256_texto(chave)
    return doc


def para_json(valor):
    """Converte recursivamente ObjectId/datetime/set em tipos serializáveis."""
    if isinstance(valor, dict):
        return {k: para_json(v) for k, v in valor.items() if k != "hash"}
    if isinstance(valor, (list, tuple)):
        return [para_json(v) for v in valor]
    if isinstance(valor, set):
        return sorted(para_json(v) for v in valor)
    if isinstance(valor, datetime):
        return valor.strftime(FORMATO_TS)
    if type(valor).__name__ == "ObjectId":
        return str(valor)
    return valor
