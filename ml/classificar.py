"""
Carrega o modelo (verificando a integridade ANTES) e pontua IPs.

Nota de segurança (Aula 12 / OWASP A08): joblib.load usa pickle, e pickle
EXECUTA código ao carregar. Por isso o hash SHA-256 do arquivo é conferido
antes do load — se alguém trocar o modelo.pkl, ele não é carregado.
"""

import hashlib
from pathlib import Path

import joblib

from ml.features import NOMES_FEATURES, vetor


class ModeloAdulterado(Exception):
    """Hash do modelo.pkl não confere com o registrado."""


def calcular_hash(caminho):
    """SHA-256 em blocos (mesma função hash_arquivo do 1º semestre, Aula 11)."""
    sha256 = hashlib.sha256()
    with open(caminho, "rb") as f:
        while bloco := f.read(8192):
            sha256.update(bloco)
    return sha256.hexdigest()


def caminho_hash(caminho_modelo):
    return Path(str(caminho_modelo) + ".sha256")


def gravar_hash(caminho_modelo):
    digest = calcular_hash(caminho_modelo)
    caminho_hash(caminho_modelo).write_text(f"{digest}  {Path(caminho_modelo).name}\n", encoding="utf-8")
    return digest


def verificar_integridade(caminho_modelo):
    """Retorna (ok: bool, hash_atual, hash_esperado)."""
    try:
        esperado = caminho_hash(caminho_modelo).read_text(encoding="utf-8").split()[0]
    except (OSError, IndexError):
        return False, None, None
    atual = calcular_hash(caminho_modelo)
    return atual == esperado, atual, esperado


def carregar_modelo(caminho_modelo):
    ok, atual, esperado = verificar_integridade(caminho_modelo)
    if not ok:
        raise ModeloAdulterado(f"ALERTA: hash do modelo não confere (atual={atual}, esperado={esperado})")
    return joblib.load(caminho_modelo)


def nivel_risco(score):
    if score >= 0.7:
        return "ALTO"
    if score >= 0.4:
        return "MEDIO"
    return "BAIXO"


def pontuar(modelo, features_por_ip):
    """
    features_por_ip: {ip: {feature: valor}} (ml.features.extrair_features)
    Retorna {ip: {"score": 0..1, "rotulo": "ataque"|"normal", "risco": "ALTO|MEDIO|BAIXO",
                  "features": {...}}} — usado para ORDENAR os alertas (prioridade).
    """
    if not features_por_ip:
        return {}
    ips = list(features_por_ip)
    X = [vetor(features_por_ip[ip]) for ip in ips]
    scores = modelo.predict_proba(X)[:, 1]
    resultado = {}
    for ip, score in zip(ips, scores):
        s = round(float(score), 3)
        resultado[ip] = {
            "score": s,
            "rotulo": "ataque" if s >= 0.5 else "normal",
            "risco": nivel_risco(s),
            "features": {n: features_por_ip[ip][n] for n in NOMES_FEATURES},
        }
    return resultado


if __name__ == "__main__":
    import settings
    from core.blacklist import carregar_blacklist
    from core.coletor import carregar_todos_os_logs
    from ml.features import extrair_features

    ok, atual, esperado = verificar_integridade(settings.ARQUIVO_MODELO)
    print(f"Hash confere: {'SIM — modelo íntegro' if ok else 'NÃO — ALERTA: modelo alterado!'}")
    if ok:
        modelo = carregar_modelo(settings.ARQUIVO_MODELO)
        feats = extrair_features(carregar_todos_os_logs(str(settings.PASTA_LOGS)),
                                 carregar_blacklist(settings.ARQUIVO_BLACKLIST))
        for ip, r in sorted(pontuar(modelo, feats).items(), key=lambda x: -x[1]["score"]):
            print(f"{ip:<16} score={r['score']:.2f} risco={r['risco']:<5} -> {r['rotulo']}")
