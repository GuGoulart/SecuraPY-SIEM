"""Carrega a blacklist (set) a partir de arquivo — antes era constante no main.py."""

import ipaddress

BLACKLIST_PADRAO = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def carregar_blacklist(caminho):
    """Lê um IP por linha, ignora comentários e IPs inválidos. Falha -> blacklist padrão."""
    ips = set()
    try:
        with open(caminho, "r", encoding="utf-8") as arquivo:
            for linha in arquivo:
                linha = linha.split("#", 1)[0].strip()
                if not linha:
                    continue
                try:
                    ips.add(str(ipaddress.ip_address(linha)))
                except ValueError:
                    print(f"[AVISO] IP inválido ignorado na blacklist: {linha!r}")
    except OSError:
        print(f"[AVISO] Blacklist não encontrada em {caminho}; usando padrão.")
        return set(BLACKLIST_PADRAO)
    return ips or set(BLACKLIST_PADRAO)
