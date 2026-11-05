import json


FAIXAS_SEVERIDADE = (
    ("CRITICA", 9),
    ("ALTA", 7),
    ("MEDIA", 5),
    ("BAIXA", 3),
)

REGRAS_PADRAO = [
    {
        "id": "R000",
        "nome": "Regra Padrão de Emergência",
        "descricao": "Login com usuário admin (regra mínima de fallback)",
        "fonte": "auth",
        "condicao": "usuario_privilegiado",
        "usuarios_alvo": ["admin", "root"],
        "severidade_base": 6,
        "ativa": True,
    }
]


def carregar_regras(caminho_config):
    try:
        with open(caminho_config, "r", encoding="utf-8") as arquivo:
            config = json.load(arquivo)
    except FileNotFoundError:
        print(f"[AVISO] Arquivo de regras não encontrado: {caminho_config}")
        print("[AVISO] Usando regras padrão de emergência.")
        return REGRAS_PADRAO
    except json.JSONDecodeError as erro:
        print(f"[AVISO] JSON de regras inválido em {caminho_config}: {erro}")
        print("[AVISO] Usando regras padrão de emergência.")
        return REGRAS_PADRAO

    regras = config.get("regras", [])
    if not regras:
        print(f"[AVISO] Nenhuma regra encontrada em {caminho_config}. Usando regras padrão.")
        return REGRAS_PADRAO

    return regras


def classificar_severidade(pontuacao):
    for nome_severidade, minimo in FAIXAS_SEVERIDADE:
        if pontuacao >= minimo:
            return nome_severidade
    return "INFO"


def _extrair_campo(detalhes, chave):
    for parte in detalhes.split():
        if "=" in parte:
            nome_campo, valor = parte.split("=", 1)
            if nome_campo == chave:
                return valor
    return None


def avaliar_regra(regra, evento):
    if regra["fonte"] != evento["fonte"]:
        return None

    condicao = regra["condicao"]
    violou = False
    detalhe_extra = ""

    if condicao == "usuario_privilegiado":
        usuario = _extrair_campo(evento["detalhes"], "usuario")
        if evento["tipo"] == "FAIL" and usuario in regra.get("usuarios_alvo", []):
            violou = True
            detalhe_extra = f"usuário '{usuario}'"

    elif condicao == "porta_critica":
        porta_str = _extrair_campo(evento["detalhes"], "dport")
        if evento["tipo"] == "BLOCK" and porta_str is not None:
            try:
                porta = int(porta_str)
            except ValueError:
                porta = None
            if porta in regra.get("portas_criticas", []):
                violou = True
                detalhe_extra = f"porta {porta}"

    elif condicao == "path_traversal":
        url = _extrair_campo(evento["detalhes"], "url") or ""
        if any(padrao in url for padrao in regra.get("padroes", [])):
            violou = True
            detalhe_extra = f"URL '{url}'"

    elif condicao == "xss":
        url = _extrair_campo(evento["detalhes"], "url") or ""
        if any(padrao in url for padrao in regra.get("padroes", [])):
            violou = True
            detalhe_extra = f"URL '{url}'"

    elif condicao == "reconhecimento":
        url = _extrair_campo(evento["detalhes"], "url") or ""
        if any(url_suspeita in url for url_suspeita in regra.get("urls_suspeitas", [])):
            violou = True
            detalhe_extra = f"URL '{url}'"

    if not violou:
        return None

    severidade = classificar_severidade(regra["severidade_base"])

    alerta = {
        "timestamp": evento["timestamp"],
        "regra": regra["nome"],
        "regra_id": regra.get("id", ""),
        "severidade": severidade,
        "pontuacao": regra["severidade_base"],
        "ip": evento["ip"],
        "descricao": f"{regra['descricao']} ({detalhe_extra})",
    }
    return alerta


def aplicar_regras(eventos, regras):
    regras_ativas = [regra for regra in regras if regra.get("ativa", True)]

    alertas = []
    for evento in eventos:
        for regra in regras_ativas:
            alerta = avaliar_regra(regra, evento)
            if alerta is not None:
                alertas.append(alerta)

    return alertas


if __name__ == "__main__":
    print("=== Teste isolado de regras.py ===")

    regras_teste = carregar_regras("config/regras.json")
    print(f"{len(regras_teste)} regra(s) carregada(s).")

    eventos_teste = [
        {
            "timestamp": "2025-02-20 08:15:01",
            "fonte": "auth",
            "tipo": "FAIL",
            "ip": "185.220.101.1",
            "detalhes": "usuario=admin",
            "linha_original": "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1",
        },
        {
            "timestamp": "2025-02-20 08:10:02",
            "fonte": "firewall",
            "tipo": "BLOCK",
            "ip": "185.220.101.1",
            "detalhes": "proto=TCP dst=10.0.0.1 dport=22",
            "linha_original": "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22",
        },
        {
            "timestamp": "2025-02-20 08:20:08",
            "fonte": "web",
            "tipo": "GET",
            "ip": "91.240.118.172",
            "detalhes": "url=/../../etc/passwd status=400",
            "linha_original": "2025-02-20 08:20:08 GET url=/../../etc/passwd ip=91.240.118.172 status=400",
        },
        {
            "timestamp": "2025-02-20 08:20:01",
            "fonte": "web",
            "tipo": "GET",
            "ip": "192.168.1.10",
            "detalhes": "url=/index.html status=200",
            "linha_original": "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200",
        },
    ]

    alertas_teste = aplicar_regras(eventos_teste, regras_teste)
    print(f"{len(alertas_teste)} alerta(s) gerado(s):")
    for alerta in alertas_teste:
        print(f"  [{alerta['severidade']}] {alerta['regra']} — {alerta['ip']} — {alerta['descricao']}")