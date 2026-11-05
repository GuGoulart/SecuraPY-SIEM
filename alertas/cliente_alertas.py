import socket
import threading
import sys

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):

    while True:
        try:
            dados = cliente.recv(4096)
            if not dados:
                print("\n[SISTEMA] Servidor encerrou a conexão.")
                break
            print(dados.decode("utf-8"), end="", flush=True)
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            print("\n[SISTEMA] Conexão com o servidor perdida.")
            break


def conectar_servidor(host=HOST, porta=PORTA):
   
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cliente.connect((host, porta))
        print(f"Conectado ao SecuraPy SIEM ({host}:{porta})")
    except ConnectionRefusedError:
        print(f"[ERRO] Não foi possível conectar ao servidor em {host}:{porta}.")
        print("Certifique-se de que o 'servidor_alertas.py' está em execução.")
        return

    thread_escuta = threading.Thread(
        target=receber_alertas,
        args=(cliente,),
        daemon=True
    )
    thread_escuta.start()

    try:
        while True:
            comando = input()
            if not comando.strip():
                continue

            try:
                cliente.sendall(comando.strip().encode("utf-8"))
            except (BrokenPipeError, OSError):
                break

            if comando.strip() == "/sair":
                break

    except (KeyboardInterrupt, EOFError):
        print("\nDesconectando...")
        try:
            cliente.sendall("/sair".encode("utf-8"))
        except Exception:
            pass
    finally:
        cliente.close()


if __name__ == "__main__":
    # [GS] uso: python alertas/cliente_alertas.py [host] [porta]
    host_arg = sys.argv[1] if len(sys.argv) > 1 else HOST
    porta_arg = int(sys.argv[2]) if len(sys.argv) > 2 else PORTA
    conectar_servidor(host_arg, porta_arg)
