"""
Módulo 5 — Enriquecimento de IPs (enriquecimento.py)

Consulta a API pública ipinfo.io para obter geolocalização e organização
de IPs suspeitos, classificando previamente se o IP é privado (RFC 1918)
ou público, e usando cache para evitar consultas repetidas.
"""

import ipaddress
import os
import threading
import time

import requests

# [GS] Melhorias do 2º semestre (Aula 10):
#   - validação/classificação com o módulo ipaddress (substitui o parser manual)
#   - token opcional do ipinfo via variável de ambiente (nunca no código)
#   - backoff exponencial em 429 (rate limit)
#   - chave ENRIQUECIMENTO_ATIVO=false para demos offline
#   - lock no cache (a API Flask atende requisições em várias threads)
_lock_cache = threading.Lock()


def eh_ip_valido(ip):
    """[GS] True se `ip` é um IPv4/IPv6 sintaticamente válido."""
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


def eh_ip_privado(ip):
    """
    Verifica se um IP é de rede privada/reservada.
    [GS] Agora usa ipaddress (cobre RFC 1918, loopback, link-local e IPv6).
    IP inválido -> False (mesmo comportamento do 1º semestre).
    """
    try:
        obj = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return obj.is_private or obj.is_loopback or obj.is_link_local


def consultar_ip(ip, cache):
    """
    Consulta ipinfo.io para obter dados do IP.
    Usa cache (dict) para evitar consultas repetidas.
    Retorna dict com: ip, cidade, regiao, pais, org, hostname
    """
    # Se já está no cache, retorna direto (evita nova chamada HTTP)
    if ip in cache:
        return cache[ip]

    # IPs privados não precisam ser consultados na API externa
    if eh_ip_privado(ip):
        dados = {
            "ip": ip,
            "cidade": "Rede Interna",
            "regiao": "Rede Interna",
            "pais": "Rede Interna",
            "org": "Rede Interna",
            "hostname": "Rede Interna",
        }
        cache[ip] = dados
        return dados

    dados_padrao = {
        "ip": ip,
        "cidade": "Desconhecido",
        "regiao": "Desconhecido",
        "pais": "Desconhecido",
        "org": "Desconhecido",
        "hostname": "Desconhecido",
    }

    # [GS] IP inválido ou enriquecimento desligado: não sai para a rede
    if not eh_ip_valido(ip) or os.environ.get("ENRIQUECIMENTO_ATIVO", "true").lower() != "true":
        with _lock_cache:
            cache[ip] = dados_padrao
        return dados_padrao

    url = f"https://ipinfo.io/{ip}/json"
    headers = {}
    token = os.environ.get("IPINFO_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resposta = None
        for tentativa in range(3):                      # [GS] backoff: 1s, 2s
            resposta = requests.get(url, headers=headers, timeout=5)
            if resposta.status_code != 429:
                break
            if tentativa < 2:
                time.sleep(2 ** tentativa)

        if resposta.status_code == 200:
            try:
                dados_api = resposta.json()
            except ValueError:                          # [GS] JSON inválido da API
                dados_api = {}
            dados = {
                "ip": ip,
                "cidade": dados_api.get("city", "Desconhecido"),
                "regiao": dados_api.get("region", "Desconhecido"),
                "pais": dados_api.get("country", "Desconhecido"),
                "org": dados_api.get("org", "Desconhecido"),
                "hostname": dados_api.get("hostname", "Desconhecido"),
            }
        elif resposta.status_code == 429:
            print(f"[AVISO] Limite de requisições atingido ao consultar {ip} (status 429).")
            dados = dados_padrao
        else:
            print(f"[AVISO] Falha ao consultar {ip} (status {resposta.status_code}).")
            dados = dados_padrao

    except requests.exceptions.Timeout:
        print(f"[ERRO] Timeout ao consultar {ip}.")
        dados = dados_padrao
    except requests.exceptions.ConnectionError:
        print(f"[ERRO] Falha de conexão ao consultar {ip} (API indisponível).")
        dados = dados_padrao
    except requests.exceptions.HTTPError as erro:
        print(f"[ERRO] Erro HTTP ao consultar {ip}: {erro}")
        dados = dados_padrao
    except requests.exceptions.RequestException as erro:
        print(f"[ERRO] Erro inesperado ao consultar {ip}: {erro}")
        dados = dados_padrao

    cache[ip] = dados
    return dados


def enriquecer_alertas(alertas, cache):
    """
    Recebe lista de alertas e adiciona informações de geolocalização.
    Pula IPs privados (marca como "Rede Interna").
    Retorna alertas enriquecidos.
    """
    alertas_enriquecidos = []

    for alerta in alertas:
        ip = alerta.get("ip")
        dados_ip = consultar_ip(ip, cache)

        alerta_enriquecido = dict(alerta)
        alerta_enriquecido["enriquecimento"] = dados_ip
        alertas_enriquecidos.append(alerta_enriquecido)

    return alertas_enriquecidos


def exibir_enriquecimento(dados_ip):
    """Exibe as informações do IP de forma formatada."""
    print(f"IP:        {dados_ip.get('ip', '-')}")
    print(f"Cidade:    {dados_ip.get('cidade', '-')}")
    print(f"Região:    {dados_ip.get('regiao', '-')}")
    print(f"País:      {dados_ip.get('pais', '-')}")
    print(f"Org:       {dados_ip.get('org', '-')}")
    print(f"Hostname:  {dados_ip.get('hostname', '-')}")


if __name__ == "__main__":
    # Testes rápidos do módulo isolado (cenários do enunciado)
    cache_teste = {}

    print("--- Teste 1: IP público conhecido (8.8.8.8) ---")
    exibir_enriquecimento(consultar_ip("8.8.8.8", cache_teste))

    print("\n--- Teste 2: IP privado (192.168.1.10) ---")
    exibir_enriquecimento(consultar_ip("192.168.1.10", cache_teste))

    print("\n--- Teste 3: mesmo IP consultado de novo (deve vir do cache) ---")
    exibir_enriquecimento(consultar_ip("8.8.8.8", cache_teste))

    print("\n--- Teste 4: IP inválido (999.999.999.999) ---")
    exibir_enriquecimento(consultar_ip("999.999.999.999", cache_teste))