"""
Verifica, via Docker SDK for Python (Aula 11), se os 3 contêineres da
plataforma estão "running". Rode NO HOST (precisa do Docker local):

    python scripts/status_containers.py

Saída 0 = tudo rodando; 1 = algum parado/ausente; 2 = Docker inacessível.
"""

import sys

try:
    import docker
    from docker.errors import DockerException, NotFound
except ImportError:
    print("Instale o SDK: pip install docker")
    sys.exit(2)

ESPERADOS = ("securapy-api", "securapy-mongo", "securapy-mysql")


def status_containers():
    cliente = docker.from_env()
    resumo = []
    for nome in ESPERADOS:
        try:
            c = cliente.containers.get(nome)
            saude = (c.attrs.get("State", {}).get("Health") or {}).get("Status", "-")
            imagem = c.image.tags[0] if c.image.tags else c.image.short_id
            resumo.append({"nome": nome, "status": c.status, "saude": saude, "imagem": imagem})
        except NotFound:
            resumo.append({"nome": nome, "status": "ausente", "saude": "-", "imagem": "-"})
    return resumo


def main():
    try:
        resumo = status_containers()
    except DockerException as erro:
        print(f"Não foi possível falar com o Docker: {erro}")
        return 2
    print(f"{'NOME':<16} {'STATUS':<10} {'SAÚDE':<10} IMAGEM")
    for c in resumo:
        marca = "" if c["status"] == "running" else "   <- ⚠️  NÃO ESTÁ RODANDO"
        print(f"{c['nome']:<16} {c['status']:<10} {c['saude']:<10} {c['imagem']}{marca}")
    rodando = sum(c["status"] == "running" for c in resumo)
    print(f"\nTotal: {len(resumo)} | Rodando: {rodando} | Parados/ausentes: {len(resumo) - rodando}")
    return 0 if rodando == len(resumo) else 1


if __name__ == "__main__":
    sys.exit(main())
