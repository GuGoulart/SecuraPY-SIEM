"""
[BÔNUS] Detecção de anomalias com Isolation Forest (Aula 4.6).

Diferente do classificador (supervisionado), aqui não há rótulo: o modelo
aprende o "normal" do próprio ambiente e marca quem foge do padrão —
útil para comportamentos que nenhuma regra descreve.
"""

import numpy as np
from sklearn.ensemble import IsolationForest

from ml.features import vetor


def detectar_anomalias(features_por_ip, contamination=0.3, random_state=42):
    """Retorna {ip: {"anomalia": bool, "score_anomalia": float}} (score menor = mais anômalo)."""
    ips = list(features_por_ip)
    if len(ips) < 4:  # com pouquíssimos pontos o "normal" não é estimável
        return {ip: {"anomalia": False, "score_anomalia": 0.0} for ip in ips}
    X = np.array([vetor(features_por_ip[ip]) for ip in ips])
    detector = IsolationForest(contamination=contamination, random_state=random_state)
    rotulos = detector.fit_predict(X)            # 1 = normal, -1 = anomalia
    scores = detector.score_samples(X)
    return {ip: {"anomalia": bool(r == -1), "score_anomalia": round(float(s), 3)}
            for ip, r, s in zip(ips, rotulos, scores)}


if __name__ == "__main__":
    import settings
    from core.blacklist import carregar_blacklist
    from core.coletor import carregar_todos_os_logs
    from ml.features import extrair_features

    feats = extrair_features(carregar_todos_os_logs(str(settings.PASTA_LOGS)),
                             carregar_blacklist(settings.ARQUIVO_BLACKLIST))
    print("\n=== Isolation Forest por IP ===")
    for ip, r in detectar_anomalias(feats).items():
        print(f"{ip:<16} {list(feats[ip].values())} -> {'ANOMALIA' if r['anomalia'] else 'Normal'}")
