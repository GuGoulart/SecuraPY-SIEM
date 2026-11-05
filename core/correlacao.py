"""
[BÔNUS] Correlação temporal — brute force em JANELA de tempo.

O detector do 1º semestre conta o TOTAL de falhas por IP. Um SOC olha a
janela: 10 falhas em 30 segundos é ataque; 10 falhas espalhadas em um mês
provavelmente é usuário esquecido. Aqui usamos janela deslizante
(two pointers) sobre os timestamps ordenados de cada IP.
"""

from datetime import datetime

FORMATO_TS = "%Y-%m-%d %H:%M:%S"


def _ts(evento):
    valor = evento["timestamp"]
    return valor if isinstance(valor, datetime) else datetime.strptime(str(valor), FORMATO_TS)


def detectar_brute_force_janela(eventos, janela_segundos=60, limite=5):
    """
    Retorna {ip: {"max_na_janela": N, "inicio": str, "fim": str,
                  "janela_segundos": J, "severidade": "..."}}
    apenas para IPs com pelo menos `limite` FAILs dentro de alguma janela.
    """
    falhas = {}
    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            try:
                falhas.setdefault(evento["ip"], []).append(_ts(evento))
            except (ValueError, KeyError):
                continue  # timestamp malformado não derruba a correlação

    resultado = {}
    for ip, tempos in falhas.items():
        tempos.sort()
        melhor, inicio_melhor, fim_melhor = 0, None, None
        esquerda = 0
        for direita, t in enumerate(tempos):
            while (t - tempos[esquerda]).total_seconds() > janela_segundos:
                esquerda += 1
            qtd = direita - esquerda + 1
            if qtd > melhor:
                melhor, inicio_melhor, fim_melhor = qtd, tempos[esquerda], t
        if melhor >= limite:
            resultado[ip] = {
                "max_na_janela": melhor,
                "inicio": inicio_melhor.strftime(FORMATO_TS),
                "fim": fim_melhor.strftime(FORMATO_TS),
                "janela_segundos": janela_segundos,
                "severidade": "ALTA" if melhor >= 2 * limite else "MEDIA",
            }
    return resultado


def correlacao_para_alertas(resultado):
    """Converte o resultado em alertas no mesmo formato do motor de regras."""
    alertas = []
    for ip, dados in resultado.items():
        alertas.append({
            "timestamp": dados["fim"],
            "regra": "Brute force em janela de tempo",
            "regra_id": "COR-BF",
            "severidade": dados["severidade"],
            "pontuacao": 8 if dados["severidade"] == "ALTA" else 6,
            "ip": ip,
            "descricao": (f"{dados['max_na_janela']} falhas de login em até "
                          f"{dados['janela_segundos']}s ({dados['inicio']} -> {dados['fim']})"),
        })
    return alertas
