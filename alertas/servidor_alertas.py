import os
import socket
import threading
from datetime import datetime


HOST = os.environ.get("ALERTAS_HOST", "0.0.0.0")      # [GS] configurável por env
PORTA = int(os.environ.get("ALERTAS_PORTA", "9999"))
MAX_CLIENTES = 10


clientes = {}       
lock = threading.Lock()
historico_alertas = []


def formatar_alerta(alerta_dict):
    
    if isinstance(alerta_dict, str):
        return alerta_dict

    timestamp_raw = str(alerta_dict.get("timestamp", datetime.now().strftime("%H:%M:%S")))
    
    if " " in timestamp_raw:
        hora = timestamp_raw.split(" ")[1]
    elif len(timestamp_raw) >= 8 and ":" in timestamp_raw:
        hora = timestamp_raw[-8:]
    else:
        hora = timestamp_raw

    severidade = str(alerta_dict.get("severidade", "INFO")).upper()
    regra = alerta_dict.get("regra_nome", alerta_dict.get("regra", "Alerta Generalizado"))
    ip = alerta_dict.get("ip", "0.0.0.0")
    descricao = alerta_dict.get("descricao", "Sem detalhes adicionais")

    return f"[{hora}] [{severidade}] {regra} - {ip} - {descricao}"


def broadcast_alerta(alerta):
    
    if isinstance(alerta, dict):
        alerta_fmt = formatar_alerta(alerta)
    else:
        alerta_fmt = str(alerta)

    with lock:
        historico_alertas.append(alerta_fmt)
        
        if len(historico_alertas) > 200:
            historico_alertas.pop(0)

        desconectados = []
        for conexao in list(clientes.keys()):
            try:
                conexao.sendall((alerta_fmt + "\n").encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                desconectados.append(conexao)

        for conexao in desconectados:
            _remover_cliente_interno(conexao)


def _remover_cliente_interno(conexao):

    if conexao in clientes:
        endereco = clientes.pop(conexao)
        try:
            conexao.close()
        except Exception:
            pass
        hora_atual = datetime.now().strftime("%H:%M:%S")
        print(f"[{hora_atual}] Cliente desconectado: {endereco[0]}:{endereco[1]}")


def remover_cliente(conexao):

    with lock:
        _remover_cliente_interno(conexao)


def tratar_cliente(conexao, endereco):
    
    hora_atual = datetime.now().strftime("%H:%M:%S")
    print(f"[{hora_atual}] Cliente conectado: {endereco[0]}:{endereco[1]}")

    with lock:
        clientes[conexao] = endereco

    try:
        boas_vindas = (
            "=== Conectado ao SecuraPy SIEM ===\n"
            "Comandos: /status, /historico, /sair\n"
        )
        conexao.sendall(boas_vindas.encode("utf-8"))

        while True:
            dados = conexao.recv(1024)
            if not dados:
                break

            comando = dados.decode("utf-8").strip()

            if comando == "/status":
                with lock:
                    total_clientes = len(clientes)
                    total_alertas = len(historico_alertas)
                resposta = f"Clientes conectados: {total_clientes} | Alertas na sessão: {total_alertas}\n"
                conexao.sendall(resposta.encode("utf-8"))

            elif comando == "/historico":
                with lock:
                    ultimos_10 = historico_alertas[-10:]

                if not ultimos_10:
                    resposta = "Nenhum alerta registrado na sessão.\n"
                else:
                    resposta = "\n".join(ultimos_10) + "\n"
                conexao.sendall(resposta.encode("utf-8"))

            elif comando == "/sair":
                conexao.sendall("Desconectando...\n".encode("utf-8"))
                break

            elif comando:
                conexao.sendall("Comando inválido. Use: /status, /historico ou /sair\n".encode("utf-8"))

    except (ConnectionResetError, ConnectionAbortedError, OSError):
        pass
    finally:
        remover_cliente(conexao)


def iniciar_servidor(host=HOST, porta=PORTA):
   
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        servidor.bind((host, porta))
        servidor.listen(MAX_CLIENTES)
        print("=== Servidor de Alertas SecuraPy ===")
        print(f"Rodando em {host}:{porta}")
        print("Aguardando conexões...\n")

        while True:
            conexao, endereco = servidor.accept()
            thread = threading.Thread(
                target=tratar_cliente,
                args=(conexao, endereco),
                daemon=True
            )
            thread.start()

    except KeyboardInterrupt:
        print("\n[SERVIDOR] Encerrando servidor por comando de teclado...")
    except OSError as erro:  # [GS] porta em uso / bind negado não derruba a plataforma
        print(f"[SERVIDOR] Não foi possível abrir {host}:{porta} -> {erro.strerror or erro}")
    finally:
        with lock:
            for conexao in list(clientes.keys()):
                try:
                    conexao.sendall("\n[SERVIDOR] Servidor encerrado.\n".encode("utf-8"))
                    conexao.close()
                except Exception:
                    pass
            clientes.clear()
        servidor.close()
        print("[SERVIDOR] Servidor desligado com sucesso.")


_thread_servidor = None


def iniciar_em_thread(host=HOST, porta=PORTA):
    """
    [GS] Sobe o servidor TCP do 1º semestre em uma thread daemon, para rodar
    junto com a API Flask no mesmo processo. Assim a API consegue chamar
    broadcast_alerta() e os consoles conectados recebem em tempo real.
    Idempotente: chamar duas vezes não abre a porta duas vezes.
    """
    global _thread_servidor
    if _thread_servidor is not None and _thread_servidor.is_alive():
        return _thread_servidor
    _thread_servidor = threading.Thread(
        target=iniciar_servidor, args=(host, porta), daemon=True, name="servidor-alertas"
    )
    _thread_servidor.start()
    return _thread_servidor


if __name__ == "__main__":
    iniciar_servidor()
