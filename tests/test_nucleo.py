"""Módulo A — núcleo do 1º semestre integrado (A1–A4) + correlação temporal (bônus)."""

from core.blacklist import carregar_blacklist
from core.correlacao import detectar_brute_force_janela
from core.detector import detectar_brute_force, detectar_port_scan, verificar_blacklist
from core.regras import aplicar_regras, carregar_regras
import settings


def test_a1_carrega_3_logs_com_fonte(eventos):
    fontes = {}
    for e in eventos:
        fontes[e["fonte"]] = fontes.get(e["fonte"], 0) + 1
    assert len(eventos) == 58
    assert fontes == {"auth": 23, "firewall": 17, "web": 18}


def test_a2_brute_force(eventos):
    bf = detectar_brute_force(eventos)
    assert bf["185.220.101.1"]["tentativas"] == 11      # o arquivo tem 11 (enunciado cita 10)
    assert bf["185.220.101.1"]["severidade"] == "ALTA"


def test_a3_port_scan(eventos):
    ps = detectar_port_scan(eventos)
    assert ps["185.220.101.1"]["quantidade"] == 7


def test_a4_blacklist(eventos):
    ips, _ = verificar_blacklist(eventos, carregar_blacklist(settings.ARQUIVO_BLACKLIST))
    assert ips == {"185.220.101.1", "45.33.32.156", "91.240.118.172"}


def test_motor_de_regras_gera_alertas(eventos):
    alertas = aplicar_regras(eventos, carregar_regras(str(settings.ARQUIVO_REGRAS)))
    assert len(alertas) == 31
    assert any(a["severidade"] == "CRITICA" for a in alertas)  # path traversal


def test_log_inexistente_nao_trava(tmp_path):
    from core.coletor import carregar_log, carregar_todos_os_logs
    assert carregar_log(str(tmp_path / "nao_existe.log"), "auth") == []
    assert carregar_todos_os_logs(str(tmp_path / "pasta_que_nao_existe")) == []


def test_log_malformado_ignora_linha(tmp_path):
    from core.coletor import carregar_log
    arq = tmp_path / "auth.log"
    arq.write_text("linha quebrada\n2025-02-20 08:15:01 FAIL usuario=admin ip=1.2.3.4\n\x00\x00\n", encoding="utf-8")
    assert len(carregar_log(str(arq), "auth")) == 1


def test_bonus_correlacao_temporal(eventos):
    r = detectar_brute_force_janela(eventos, janela_segundos=60, limite=5)
    assert r["185.220.101.1"]["max_na_janela"] == 11
    assert "45.33.32.156" not in r          # só 3 falhas


def test_correlacao_respeita_janela():
    ev = [{"fonte": "auth", "tipo": "FAIL", "ip": "1.1.1.1", "timestamp": f"2025-02-20 08:{m:02d}:00"}
          for m in range(0, 50, 10)]       # 5 falhas, uma a cada 10 minutos
    assert detectar_brute_force_janela(ev, janela_segundos=60, limite=5) == {}
