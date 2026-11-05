"""
Exporta o relatório JSON da plataforma (entregável 4) consumindo a própria API.

    python scripts/exportar_relatorio.py [--url http://localhost:5000]

Credenciais: variáveis ADMIN_EMAIL / ADMIN_SENHA (ou digitadas no prompt).
"""

import argparse
import getpass
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:5000")
    parser.add_argument("--saida", default="saida")
    args = parser.parse_args()

    email = os.environ.get("ADMIN_EMAIL") or input("E-mail do operador: ")
    senha = os.environ.get("ADMIN_SENHA") or getpass.getpass("Senha: ")
    try:
        r = requests.post(f"{args.url}/api/auth/login", json={"email": email, "senha": senha}, timeout=10)
        if r.status_code != 200:
            print(f"Login falhou ({r.status_code}): {r.json().get('erro')}")
            return 1
        cab = {"Authorization": f"Bearer {r.json()['token']}"}
        rel = requests.get(f"{args.url}/api/relatorio", headers=cab, timeout=30)
        rel.raise_for_status()
    except requests.RequestException as erro:
        print(f"Erro ao falar com a API: {type(erro).__name__}")
        return 1

    pasta = Path(args.saida)
    pasta.mkdir(parents=True, exist_ok=True)
    caminho = pasta / datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json")
    try:
        caminho.write_text(json.dumps(rel.json(), indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as erro:
        print(f"Não foi possível salvar: {erro}")
        return 1
    print(f"Relatório exportado em: {caminho}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
