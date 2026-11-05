import json
import os
from datetime import datetime


def exibir_menu():
    opcoes_validas = range(0, 10)

    print()
    print("╔══════════════════════════════════════════╗")
    print("║         SecuraPy SIEM — Menu             ║")
    print("╠══════════════════════════════════════════╣")
    print("║  1. Carregar e processar logs            ║")
    print("║  2. Resumo geral                         ║")
    print("║  3. Filtrar eventos                      ║")
    print("║  4. Buscar IP                            ║")
    print("║  5. Top 10 IPs suspeitos                 ║")
    print("║  6. Ver alertas por severidade           ║")
    print("║  7. Enriquecer IPs suspeitos             ║")
    print("║  8. Exportar relatório JSON              ║")
    print("║  9. Iniciar servidor de alertas          ║")
    print("║  0. Sair                                 ║")
    print("╚══════════════════════════════════════════╝")

    while True:
        entrada = input("Escolha uma opção: ").strip()
        try:
            opcao = int(entrada)
        except ValueError:
            print("Opção inválida. Digite um número entre 0 e 9.")
            continue

        if opcao not in opcoes_validas:
            print("Opção inválida. Digite um número entre 0 e 9.")
            continue

        return opcao


def resumo_geral(eventos, alertas):
    contagem_por_fonte = {}
    for evento in eventos:
        fonte = evento["fonte"]
        contagem_por_fonte[fonte] = contagem_por_fonte.get(fonte, 0) + 1

    contagem_por_severidade = {}
    for alerta in alertas:
        severidade = alerta["severidade"]
        contagem_por_severidade[severidade] = contagem_por_severidade.get(severidade, 0) + 1

    print("\n=== Resumo Geral ===")
    print(f"Total de eventos: {len(eventos)}")
    for fonte, quantidade in contagem_por_fonte.items():
        print(f"  - {fonte}: {quantidade} evento(s)")

    print(f"Total de alertas: {len(alertas)}")
    for severidade, quantidade in contagem_por_severidade.items():
        print(f"  - {severidade}: {quantidade} alerta(s)")

    return {
        "eventos_por_fonte": contagem_por_fonte,
        "alertas_por_severidade": contagem_por_severidade,
        "total_eventos": len(eventos),
        "total_alertas": len(alertas),
    }


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    resultado = [
        evento for evento in eventos
        if (fonte is None or evento["fonte"] == fonte)
        and (tipo is None or evento["tipo"] == tipo)
        and (ip is None or evento["ip"] == ip)
    ]
    return resultado


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    eventos_do_ip = filtrar_eventos(eventos, ip=ip)
    alertas_do_ip = [alerta for alerta in alertas if alerta["ip"] == ip]
    dados_geo = cache_enriquecimento.get(ip)

    print(f"\n=== Relatório do IP {ip} ===")
    print(f"Eventos encontrados: {len(eventos_do_ip)}")
    for evento in eventos_do_ip:
        print(f"  [{evento['timestamp']}] ({evento['fonte']}) {evento['tipo']} — {evento['detalhes']}")

    print(f"Alertas relacionados: {len(alertas_do_ip)}")
    for alerta in alertas_do_ip:
        print(f"  [{alerta['severidade']}] {alerta['regra']} — {alerta['descricao']}")

    if dados_geo:
        print("Geolocalização:")
        print(f"  {dados_geo}")
    else:
        print("Geolocalização: não enriquecido ainda (use a opção 7 do menu).")

    return {
        "ip": ip,
        "eventos": eventos_do_ip,
        "alertas": alertas_do_ip,
        "geolocalizacao": dados_geo,
    }


def top_ips(eventos, n=10):
    contagem_por_ip = {}
    for evento in eventos:
        ip = evento["ip"]
        contagem_por_ip[ip] = contagem_por_ip.get(ip, 0) + 1

    LIMITE_SUSPEITA = 5

    lista_ips = [
        {
            "ip": ip,
            "eventos": quantidade,
            "classificacao": "🔴 Suspeito" if quantidade > LIMITE_SUSPEITA else "🟢 Normal",
        }
        for ip, quantidade in contagem_por_ip.items()
    ]

    lista_ips.sort(key=lambda item: item["eventos"], reverse=True)

    return lista_ips[:n]


def exportar_relatorio_json(dados, caminho):
    pasta = os.path.dirname(caminho)
    if pasta:
        os.makedirs(pasta, exist_ok=True)

    try:
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo, indent=2, ensure_ascii=False)
    except (OSError, TypeError) as erro:
        print(f"[ERRO] Não foi possível salvar o relatório em {caminho}: {erro}")
        return False

    print(f"Relatório exportado com sucesso em: {caminho}")
    return True


def gerar_nome_relatorio():
    return datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json")


def exibir_tabela(dados, colunas):
    if not dados:
        print("(nenhum dado para exibir)")
        return

    largura_coluna = 22

    cabecalho = "".join(f"{coluna:<{largura_coluna}}" for coluna in colunas)
    print(cabecalho)
    print("-" * len(cabecalho))

    for linha in dados:
        linha_formatada = "".join(f"{str(linha.get(coluna, '')):<{largura_coluna}}" for coluna in colunas)
        print(linha_formatada)


if __name__ == "__main__":
    print("=== Teste isolado de relatorios.py ===")

    eventos_teste = [
        {"timestamp": "2025-02-20 08:15:01", "fonte": "auth", "tipo": "FAIL",
         "ip": "185.220.101.1", "detalhes": "usuario=admin", "linha_original": ""},
        {"timestamp": "2025-02-20 08:15:02", "fonte": "auth", "tipo": "FAIL",
         "ip": "185.220.101.1", "detalhes": "usuario=root", "linha_original": ""},
        {"timestamp": "2025-02-20 08:10:02", "fonte": "firewall", "tipo": "BLOCK",
         "ip": "185.220.101.1", "detalhes": "dport=22", "linha_original": ""},
    ]

    alertas_teste = [
        {"timestamp": "2025-02-20 08:15:01", "regra": "Login com Usuário Privilegiado",
         "regra_id": "R001", "severidade": "MEDIA", "pontuacao": 6,
         "ip": "185.220.101.1", "descricao": "usuário 'admin'"},
    ]

    cache_teste = {
        "185.220.101.1": {"cidade": "Desconhecida", "pais": "??", "org": "Rede suspeita (Tor exit node)"}
    }

    resumo_geral(eventos_teste, alertas_teste)
    print()
    filtrados = filtrar_eventos(eventos_teste, fonte="auth", tipo="FAIL")
    exibir_tabela(filtrados, ["timestamp", "fonte", "tipo", "ip"])

    buscar_ip("185.220.101.1", eventos_teste, alertas_teste, cache_teste)

    print("\n=== Top IPs ===")
    exibir_tabela(top_ips(eventos_teste, n=5), ["ip", "eventos", "classificacao"])

    relatorio_final = {
        "gerado_em": datetime.now().isoformat(),
        "resumo": resumo_geral(eventos_teste, alertas_teste),
        "eventos": eventos_teste,
        "alertas": alertas_teste,
    }
    exportar_relatorio_json(relatorio_final, os.path.join("saida", gerar_nome_relatorio()))