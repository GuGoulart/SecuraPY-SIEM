"""Módulo C — ML (C1–C4) + Isolation Forest (bônus)."""

import json
import shutil

import pytest

import settings
from core.blacklist import carregar_blacklist
from ml.anomalias import detectar_anomalias
from ml.classificar import ModeloAdulterado, carregar_modelo, pontuar, verificar_integridade
from ml.features import extrair_features


@pytest.fixture(scope="module")
def modelo():
    return carregar_modelo(settings.ARQUIVO_MODELO)


@pytest.fixture
def feats(eventos):
    return extrair_features(eventos, carregar_blacklist(settings.ARQUIVO_BLACKLIST))


def test_c1_metricas_registradas():
    m = json.loads((settings.PASTA_MODELO / "metricas.json").read_text(encoding="utf-8"))
    vc = m["validacao_cruzada"]
    assert vc["folds"] == 5
    for chave in ("precision", "recall", "f1"):
        assert 0.8 <= vc[chave]["media"] <= 1.0


def test_features_reais(feats):
    assert feats["185.220.101.1"] == {"falhas_login": 11, "portas_distintas": 7, "na_blacklist": 1, "web_erros": 6}
    assert feats["192.168.1.10"] == {"falhas_login": 0, "portas_distintas": 0, "na_blacklist": 0, "web_erros": 0}


def test_c2_atacante_risco_alto(modelo, feats):
    r = pontuar(modelo, feats)["185.220.101.1"]
    assert r["rotulo"] == "ataque" and r["risco"] == "ALTO"


def test_c3_interno_normal(modelo, feats):
    assert pontuar(modelo, feats)["192.168.1.10"]["rotulo"] == "normal"


def test_c4_hash_confere():
    ok, atual, esperado = verificar_integridade(settings.ARQUIVO_MODELO)
    assert ok and atual == esperado and len(atual) == 64


def test_c4_modelo_alterado_nao_carrega(tmp_path):
    copia = tmp_path / "modelo.pkl"
    shutil.copy(settings.ARQUIVO_MODELO, copia)
    shutil.copy(str(settings.ARQUIVO_MODELO) + ".sha256", str(copia) + ".sha256")
    with open(copia, "ab") as f:
        f.write(b"adulterado")
    with pytest.raises(ModeloAdulterado):
        carregar_modelo(copia)


def test_bonus_isolation_forest(feats):
    r = detectar_anomalias(feats)
    assert r["185.220.101.1"]["anomalia"] is True
    assert r["192.168.1.10"]["anomalia"] is False
