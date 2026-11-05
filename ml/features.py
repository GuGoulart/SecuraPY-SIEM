"""
Extração de features POR IP a partir dos eventos normalizados do coletor.

Features (mesma ordem no treino e na previsão — o Pipeline garante a escala):
    falhas_login      nº de FAIL no auth.log
    portas_distintas  nº de portas distintas BLOQUEADAS no firewall (set)
    na_blacklist      1 se o IP está na blacklist, senão 0
    web_erros         nº de requisições web com status >= 400
"""

from core.regras import _extrair_campo  # reaproveita o parser de "chave=valor" do 1º sem

NOMES_FEATURES = ("falhas_login", "portas_distintas", "na_blacklist", "web_erros")


def extrair_features(eventos, blacklist):
    """Retorna {ip: {"falhas_login": n, "portas_distintas": n, "na_blacklist": 0/1, "web_erros": n}}."""
    falhas, portas, web_erros, ips = {}, {}, {}, set()
    for evento in eventos:
        ip = evento.get("ip")
        if not ip:
            continue
        ips.add(ip)
        fonte, tipo, detalhes = evento.get("fonte"), evento.get("tipo"), evento.get("detalhes", "")
        if fonte == "auth" and tipo == "FAIL":
            falhas[ip] = falhas.get(ip, 0) + 1
        elif fonte == "firewall" and tipo == "BLOCK":
            porta = _extrair_campo(detalhes, "dport")
            if porta:
                portas.setdefault(ip, set()).add(porta)
        elif fonte == "web":
            try:
                status = int(_extrair_campo(detalhes, "status") or 0)
            except ValueError:
                status = 0
            if status >= 400:
                web_erros[ip] = web_erros.get(ip, 0) + 1

    return {
        ip: {
            "falhas_login": falhas.get(ip, 0),
            "portas_distintas": len(portas.get(ip, ())),
            "na_blacklist": 1 if ip in blacklist else 0,
            "web_erros": web_erros.get(ip, 0),
        }
        for ip in sorted(ips)
    }


def vetor(features):
    """dict de features -> lista na ordem de NOMES_FEATURES."""
    return [float(features[nome]) for nome in NOMES_FEATURES]
