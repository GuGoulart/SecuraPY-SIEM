"""
Modulo 1 - Coletor de Logs
Responsavel por ler arquivos de log de diferentes fontes (auth, firewall, web),
parsear cada linha e normalizar os eventos em um formato padronizado de dicionario.

Formato padronizado de evento:
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",  # informacoes extras dependendo da fonte
    "linha_original": "..."       # linha crua do log
}
"""

import os


def parsear_linha_auth(linha):
    """
    Parseia uma linha do auth.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        Retorna None se a linha estiver em formato invalido.
    """
    linha_original = linha
    partes = linha.split()

    if len(partes) < 5:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]

    ip = ""
    usuario = ""

    for parte in partes[3:]:
        if parte.startswith("ip="):
            ip = parte[3:]
        elif parte.startswith("usuario="):
            usuario = parte[8:]

    if ip == "":
        return None

    detalhes = "usuario=" + usuario

    evento = {
        "timestamp": timestamp,
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha_original
    }

    return evento


def parsear_linha_firewall(linha):
    """
    Parseia uma linha do firewall.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        - O campo "ip" deve conter o IP de origem (src)
        - O campo "detalhes" deve conter proto, dst e dport concatenados
        Retorna None se a linha estiver em formato invalido.
    """
    linha_original = linha
    partes = linha.split()

    if len(partes) < 6:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]

    proto = ""
    src = ""
    dst = ""
    dport = ""

    for parte in partes[3:]:
        if parte.startswith("proto="):
            proto = parte[6:]
        elif parte.startswith("src="):
            src = parte[4:]
        elif parte.startswith("dst="):
            dst = parte[4:]
        elif parte.startswith("dport="):
            dport = parte[6:]

    if src == "":
        return None

    detalhes = "proto=" + proto + " dst=" + dst + " dport=" + dport

    evento = {
        "timestamp": timestamp,
        "fonte": "firewall",
        "tipo": tipo,
        "ip": src,
        "detalhes": detalhes,
        "linha_original": linha_original
    }

    return evento


def parsear_linha_web(linha):
    """
    Parseia uma linha do web_access.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        - O campo "tipo" deve conter o metodo HTTP (GET, POST, DELETE, etc.)
        - O campo "detalhes" deve conter url e status
        Retorna None se a linha estiver em formato invalido.
    """
    linha_original = linha
    partes = linha.split()

    if len(partes) < 5:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]

    url = ""
    ip = ""
    status = ""

    for parte in partes[3:]:
        if parte.startswith("url="):
            url = parte[4:]
        elif parte.startswith("ip="):
            ip = parte[3:]
        elif parte.startswith("status="):
            status = parte[7:]

    if ip == "":
        return None

    detalhes = "url=" + url + " status=" + status

    evento = {
        "timestamp": timestamp,
        "fonte": "web",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha_original
    }

    return evento


def carregar_log(caminho_arquivo, fonte):
    """
    Le um arquivo de log e retorna uma lista de eventos normalizados.

    Parametros:
        caminho_arquivo (str): caminho do arquivo de log
        fonte (str): tipo da fonte - "auth", "firewall" ou "web"

    Retorna:
        list[dict]: lista de eventos normalizados (dicionarios)
        Retorna lista vazia se o arquivo nao existir ou estiver vazio.
    """
    eventos = []

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:  # [GS] encoding explicito
            linhas = arquivo.readlines()
    except FileNotFoundError:
        print("Erro: arquivo nao encontrado -> " + caminho_arquivo)
        return eventos
    except (UnicodeDecodeError, OSError) as erro:  # [GS] log binario/ilegivel nao trava a ingestao
        print("Erro: nao foi possivel ler " + caminho_arquivo + " -> " + type(erro).__name__)
        return eventos

    if len(linhas) == 0:
        print("Aviso: arquivo vazio -> " + caminho_arquivo)
        return eventos

    for linha in linhas:
        linha = linha.strip()

        if linha == "":
            continue

        evento = None

        if fonte == "auth":
            evento = parsear_linha_auth(linha)
        elif fonte == "firewall":
            evento = parsear_linha_firewall(linha)
        elif fonte == "web":
            evento = parsear_linha_web(linha)
        else:
            print("Aviso: fonte desconhecida -> " + fonte)

        if evento is None:
            print("Aviso: linha mal formatada, ignorada -> " + linha)
        else:
            eventos.append(evento)

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """
    Le todos os arquivos de log da pasta e retorna uma lista unificada de eventos.

    Parametros:
        pasta_logs (str): caminho da pasta contendo os arquivos de log

    Retorna:
        list[dict]: lista com todos os eventos de todas as fontes
    """
    eventos_totais = []

    try:
        arquivos = os.listdir(pasta_logs)
    except FileNotFoundError:
        print("Erro: pasta de logs nao encontrada -> " + pasta_logs)
        return eventos_totais

    for nome_arquivo in sorted(arquivos):  # [GS] ordem deterministica
        if not nome_arquivo.endswith(".log"):
            continue

        if "auth" in nome_arquivo:
            fonte = "auth"
        elif "firewall" in nome_arquivo:
            fonte = "firewall"
        elif "web" in nome_arquivo:
            fonte = "web"
        else:
            print("Aviso: nao foi possivel identificar a fonte -> " + nome_arquivo)
            continue

        caminho_completo = os.path.join(pasta_logs, nome_arquivo)
        eventos_arquivo = carregar_log(caminho_completo, fonte)

        print(nome_arquivo + ": " + str(len(eventos_arquivo)) + " eventos carregados")

        eventos_totais.extend(eventos_arquivo)

    return eventos_totais


if __name__ == "__main__":
    # Teste rapido e isolado do modulo, sem depender do resto do sistema
    print("== Teste do coletor.py ==")

    eventos = carregar_todos_os_logs("logs")
    print("Total de eventos carregados: " + str(len(eventos)))

    if len(eventos) > 0:
        print("Exemplo de evento normalizado:")
        print(eventos[0])
