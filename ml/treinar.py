"""
Treina o classificador de risco por IP (Aulas 4 e 12).

    python -m ml.treinar

Etapas:
  1. Dados REAIS: features dos 7 IPs dos logs da GS (via núcleo do 1º sem).
  2. Dados SINTÉTICOS (random_state=42): 7 amostras não bastam para validação
     cruzada de 5 folds (a menor classe teria 3 exemplos). Geramos perfis de
     tráfego normal e de ataque — inclusive casos "difíceis" (usuário que
     erra a senha algumas vezes) e 3% de ruído de rótulo — para o modelo não
     decorar a regra e as métricas não saírem artificialmente perfeitas.
  3. Torneio RandomForest x SVM x KNN, todos dentro de Pipeline
     (StandardScaler + modelo), com StratifiedKFold(5) — Aula 12.
  4. O vencedor é treinado no sintético e AVALIADO NOS LOGS REAIS (dado que o
     modelo nunca viu) — esse é o teste honesto de generalização.
  5. Modelo final (sintético + real) salvo com joblib + hash SHA-256 (A08).

Rótulo dos IPs reais: 1 (ataque) para os IPs com comportamento malicioso
confirmado nos logs (brute force/port scan/payloads web) — que coincidem
com a blacklist; 0 para os IPs internos. Limitação assumida e documentada:
com dados de laboratório o rótulo vem do conhecimento do analista.
"""

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_validate
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

import settings
from core.blacklist import carregar_blacklist
from core.coletor import carregar_todos_os_logs
from ml.classificar import gravar_hash
from ml.features import NOMES_FEATURES, extrair_features, vetor

SEMENTE = 42
IPS_ATAQUE_CONHECIDOS = {"185.220.101.1", "91.240.118.172", "45.33.32.156"}


def dados_reais(pasta_logs=None):
    eventos = carregar_todos_os_logs(str(pasta_logs or settings.PASTA_LOGS))
    blacklist = carregar_blacklist(settings.ARQUIVO_BLACKLIST)
    feats = extrair_features(eventos, blacklist)
    ips = sorted(feats)
    X = np.array([vetor(feats[ip]) for ip in ips])
    y = np.array([1 if ip in IPS_ATAQUE_CONHECIDOS else 0 for ip in ips])
    return ips, X, y, feats


def dados_sinteticos(n_normal=300, n_ataque=200, semente=SEMENTE):
    rng = np.random.RandomState(semente)
    linhas, rotulos = [], []

    def add(f, p, b, w, y):
        linhas.append([f, p, b, w])
        rotulos.append(y)

    for _ in range(n_normal):
        if rng.rand() < 0.15:  # "difícil": usuário que erra a senha / páginas quebradas
            add(rng.randint(2, 6), rng.randint(0, 2), int(rng.rand() < 0.03), rng.randint(1, 4), 0)
        else:
            add(min(rng.poisson(0.6), 3), int(rng.rand() < 0.15), int(rng.rand() < 0.02),
                min(rng.poisson(0.8), 3), 0)

    for _ in range(n_ataque):
        perfil = rng.choice(["brute", "scan", "web", "misto"])
        bl = int(rng.rand() < (0.7 if perfil == "misto" else 0.4))
        if perfil == "brute":
            add(rng.randint(4, 31), rng.randint(0, 3), bl, rng.poisson(1.5), 1)
        elif perfil == "scan":
            add(rng.poisson(0.5), rng.randint(3, 26), bl, rng.poisson(1.0), 1)
        elif perfil == "web":
            add(rng.poisson(0.5), rng.randint(0, 2), bl, rng.randint(3, 16), 1)
        else:
            add(rng.randint(2, 16), rng.randint(2, 11), bl, rng.randint(2, 9), 1)

    X, y = np.array(linhas, dtype=float), np.array(rotulos)
    ruido = rng.rand(len(y)) < 0.03                      # 3% de rótulos trocados
    y[ruido] = 1 - y[ruido]
    return X, y


def candidatos():
    def pipe(modelo):
        return Pipeline([("scaler", StandardScaler()), ("classifier", modelo)])

    return {
        "RandomForest": pipe(RandomForestClassifier(n_estimators=100, random_state=SEMENTE)),
        # SVC(probability=True) foi descontinuado no scikit-learn 1.9 -> calibração explícita
        "SVM": pipe(CalibratedClassifierCV(SVC(random_state=SEMENTE), ensemble=False)),
        "KNN": pipe(KNeighborsClassifier(n_neighbors=5)),
    }


def _r(valor):
    return round(float(valor), 3)


def treinar(pasta_saida=None, verbose=True):
    log = print if verbose else (lambda *a, **k: None)
    pasta_saida = Path(pasta_saida or settings.PASTA_MODELO)
    pasta_saida.mkdir(parents=True, exist_ok=True)

    ips, X_real, y_real, feats_reais = dados_reais()
    X_sint, y_sint = dados_sinteticos()
    log(f"\nDados reais: {len(ips)} IPs ({int(y_real.sum())} ataque) | "
        f"sintéticos: {len(y_sint)} ({int(y_sint.sum())} ataque)")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEMENTE)
    metricas_cv = ("precision", "recall", "f1")

    log("\n=== Torneio (validação cruzada 5 folds, F1) ===")
    torneio = {}
    for nome, modelo in candidatos().items():
        res = cross_validate(modelo, X_sint, y_sint, cv=cv, scoring=metricas_cv)
        torneio[nome] = {m: {"media": _r(res[f"test_{m}"].mean()), "desvio": _r(res[f"test_{m}"].std())}
                         for m in metricas_cv}
        log(f"{nome:<13} F1 {torneio[nome]['f1']['media']:.3f} (+/- {torneio[nome]['f1']['desvio']:.3f})")
    vencedor = max(torneio, key=lambda n: torneio[n]["f1"]["media"])
    log(f"Vencedor: {vencedor}")

    modelo = candidatos()[vencedor]
    pred_cv = cross_val_predict(modelo, X_sint, y_sint, cv=cv)
    matriz_cv = confusion_matrix(y_sint, pred_cv).tolist()

    # Generalização: treina SÓ no sintético, testa nos logs reais (nunca vistos)
    modelo.fit(X_sint, y_sint)
    pred_real = modelo.predict(X_real)
    proba_real = modelo.predict_proba(X_real)[:, 1]
    holdout = {
        "precisao": _r(precision_score(y_real, pred_real, zero_division=0)),
        "recall": _r(recall_score(y_real, pred_real, zero_division=0)),
        "f1": _r(f1_score(y_real, pred_real, zero_division=0)),
        "matriz_confusao": confusion_matrix(y_real, pred_real, labels=[0, 1]).tolist(),
        "por_ip": {ip: {"features": feats_reais[ip], "real": int(y), "previsto": int(p), "score": _r(s)}
                   for ip, y, p, s in zip(ips, y_real, pred_real, proba_real)},
    }

    # Modelo final: sintético + real
    modelo_final = candidatos()[vencedor]
    modelo_final.fit(np.vstack([X_sint, X_real]), np.concatenate([y_sint, y_real]))
    caminho_modelo = pasta_saida / "modelo.pkl"
    joblib.dump(modelo_final, caminho_modelo)
    digest = gravar_hash(caminho_modelo)

    metricas = {
        "features": list(NOMES_FEATURES),
        "modelo": vencedor,
        "pipeline": "StandardScaler -> " + vencedor,
        "validacao_cruzada": {"folds": 5, **torneio[vencedor], "matriz_confusao": matriz_cv},
        "torneio": torneio,
        "teste_logs_reais": holdout,
        "sha256_modelo": digest,
        "aviso": ("Acurácia omitida de propósito: com classes desbalanceadas ela mascara "
                  "ataques perdidos. Em SOC, recall (ataques pegos) e precisão (alarmes "
                  "falsos) dizem mais."),
    }
    (pasta_saida / "metricas.json").write_text(json.dumps(metricas, indent=2, ensure_ascii=False),
                                               encoding="utf-8")

    vc = metricas["validacao_cruzada"]
    log("\n=== Relatório de métricas (validação cruzada, modelo vencedor) ===")
    log(f"Precisão: {vc['precision']['media']:.3f} (+/- {vc['precision']['desvio']:.3f})")
    log(f"Recall:   {vc['recall']['media']:.3f} (+/- {vc['recall']['desvio']:.3f})")
    log(f"F1:       {vc['f1']['media']:.3f} (+/- {vc['f1']['desvio']:.3f})")
    log(f"Matriz de confusão [[VN FP] [FN VP]]: {matriz_cv}")
    log("\n=== Teste nos logs reais (dados nunca vistos no treino) ===")
    log(f"Precisão {holdout['precisao']:.2f} | Recall {holdout['recall']:.2f} | F1 {holdout['f1']:.2f}")
    for ip, info in holdout["por_ip"].items():
        rotulo = "ataque" if info["previsto"] else "normal"
        log(f"  {ip:<16} score={info['score']:.2f} -> {rotulo}")
    log(f"\nModelo salvo: {caminho_modelo}")
    log(f"SHA-256: {digest}")
    return metricas


if __name__ == "__main__":
    treinar()
