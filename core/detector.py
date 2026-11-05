"""
Modulo 3 - Detector de Anomalias
Analisa o conjunto de eventos para identificar padroes de ataque
que so ficam visiveis quando multiplos eventos sao correlacionados.

Detecta:
- Brute Force: muitas tentativas de login falhas do mesmo IP
- Port Scan: mesmo IP tentando acessar muitas portas distintas
- IPs em Blacklist: IPs conhecidamente maliciosos presentes nos logs
"""


def detectar_brute_force(eventos, threshold=5):
    """
    Identifica IPs com muitas tentativas de login falhas.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        threshold (int): numero minimo de falhas para considerar brute force

    Retorna:
        dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
        Apenas IPs com tentativas >= threshold sao incluidos.

    Classificacao de severidade:
        > 20 tentativas: "CRITICA"
        > 10 tentativas: "ALTA"
        > 5  tentativas: "MEDIA"
        >= threshold:    "BAIXA"
    """
    contagem = {}
    usuarios = {}

    for evento in eventos:
        if evento["fonte"] == "auth" and evento["tipo"] == "FAIL":
            ip = evento["ip"]

            contagem[ip] = contagem.get(ip, 0) + 1

            if ip not in usuarios:
                usuarios[ip] = set()

            usuario = evento["detalhes"].replace("usuario=", "")
            usuarios[ip].add(usuario)

    resultado = {}

    for ip in contagem:
        tentativas = contagem[ip]

        if tentativas > 20:
            severidade = "CRITICA"
        elif tentativas > 10:
            severidade = "ALTA"
        elif tentativas > 5:
            severidade = "MEDIA"
        else:
            severidade = "BAIXA"

        resultado[ip] = {
            "tentativas": tentativas,
            "usuarios": list(usuarios[ip]),
            "severidade": severidade
        }

    resultado_filtrado = {}
    for ip in resultado:
        if resultado[ip]["tentativas"] >= threshold:
            resultado_filtrado[ip] = resultado[ip]

    return resultado_filtrado


def detectar_port_scan(eventos, threshold=3):
    """
    Identifica IPs que tentaram acessar muitas portas distintas.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        threshold (int): numero minimo de portas unicas para considerar port scan

    Retorna:
        dict: {ip: {"portas": set(...), "quantidade": N, "severidade": "..."}}
        Apenas IPs com portas unicas >= threshold sao incluidos.

    Classificacao de severidade:
        > 10 portas: "CRITICA"
        > 5  portas: "ALTA"
        >= threshold: "MEDIA"
    """
    portas_por_ip = {}

    for evento in eventos:
        if evento["fonte"] == "firewall" and evento["tipo"] == "BLOCK":
            ip = evento["ip"]

            if ip not in portas_por_ip:
                portas_por_ip[ip] = set()

            detalhes = evento["detalhes"]
            posicao = detalhes.find("dport=")

            if posicao != -1:
                porta = detalhes[posicao + len("dport="):]
                porta = porta.split()[0]
                portas_por_ip[ip].add(porta)

    resultado = {}

    for ip in portas_por_ip:
        quantidade = len(portas_por_ip[ip])

        if quantidade > 10:
            severidade = "CRITICA"
        elif quantidade > 5:
            severidade = "ALTA"
        else:
            severidade = "MEDIA"

        resultado[ip] = {
            "portas": portas_por_ip[ip],
            "quantidade": quantidade,
            "severidade": severidade
        }

    resultado_filtrado = {}
    for ip in resultado:
        if resultado[ip]["quantidade"] >= threshold:
            resultado_filtrado[ip] = resultado[ip]

    return resultado_filtrado


def verificar_blacklist(eventos, blacklist):
    """
    Cruza os IPs encontrados nos eventos com uma blacklist conhecida.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        blacklist (set): conjunto de IPs maliciosos conhecidos

    Retorna:
        tuple: (ips_encontrados, contagem_por_ip)
        - ips_encontrados (set): IPs que estao na blacklist E nos eventos
        - contagem_por_ip (dict): {ip: numero_de_eventos} para cada IP da blacklist
    """
    ips_eventos = set()
    for evento in eventos:
        ips_eventos.add(evento["ip"])

    ips_encontrados = ips_eventos & blacklist

    contagem_por_ip = {}
    for evento in eventos:
        ip = evento["ip"]
        if ip in ips_encontrados:
            contagem_por_ip[ip] = contagem_por_ip.get(ip, 0) + 1

    return (ips_encontrados, contagem_por_ip)


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    """
    Consolida todas as deteccoes em um resumo unificado de ameacas.

    Parametros:
        brute_force (dict): resultado de detectar_brute_force()
        port_scan (dict): resultado de detectar_port_scan()
        blacklist_resultado (tuple): resultado de verificar_blacklist() -> (set, dict)

    Retorna:
        list[dict]: lista de ameacas ordenada por pontuacao (maior primeiro)
        Cada ameaca eh um dict com:
        {
            "ip": "185.220.101.1",
            "deteccoes": ["brute_force", "port_scan", "blacklist"],
            "pontuacao": 15,
            "severidade": "CRITICA",
            "detalhes": { ... resumo de cada deteccao ... }
        }
    """
    ips_blacklist = blacklist_resultado[0]
    contagem_blacklist = blacklist_resultado[1]

    todos_ips = set(brute_force.keys()) | set(port_scan.keys()) | ips_blacklist

    ameacas = []

    for ip in todos_ips:
        deteccoes = []
        pontuacao = 0
        detalhes = {}

        if ip in brute_force:
            deteccoes.append("brute_force")
            pontuacao = pontuacao + 5
            detalhes["brute_force"] = brute_force[ip]

        if ip in port_scan:
            deteccoes.append("port_scan")
            pontuacao = pontuacao + 5
            detalhes["port_scan"] = port_scan[ip]

        if ip in ips_blacklist:
            deteccoes.append("blacklist")
            pontuacao = pontuacao + 5
            detalhes["blacklist"] = contagem_blacklist.get(ip, 0)

        if pontuacao >= 15:
            severidade = "CRITICA"
        elif pontuacao >= 10:
            severidade = "ALTA"
        elif pontuacao >= 5:
            severidade = "MEDIA"
        else:
            severidade = "BAIXA"

        ameaca = {
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": severidade,
            "detalhes": detalhes
        }

        ameacas.append(ameaca)

    ameacas_ordenadas = sorted(ameacas, key=lambda ameaca: ameaca["pontuacao"], reverse=True)

    return ameacas_ordenadas


if __name__ == "__main__":
    # Teste rapido e isolado do modulo, usando o coletor para carregar os logs reais
    from core.coletor import carregar_todos_os_logs

    print("== Teste do detector.py ==")

    eventos = carregar_todos_os_logs("logs")

    blacklist = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

    bf = detectar_brute_force(eventos)
    ps = detectar_port_scan(eventos)
    bl = verificar_blacklist(eventos, blacklist)

    print("\nBrute force detectado:")
    print(bf)

    print("\nPort scan detectado:")
    print(ps)

    print("\nIPs em blacklist encontrados:")
    print(bl)

    resumo = gerar_resumo_ameacas(bf, ps, bl)

    print("\nResumo consolidado de ameacas:")
    for ameaca in resumo:
        print(ameaca)
