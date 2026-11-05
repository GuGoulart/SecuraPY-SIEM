"""
Repositório de USUÁRIOS/OPERADORES no MySQL (Aula 3; patterns Aulas 2 e 6).

Por que MySQL aqui: credenciais e permissões precisam de integridade
(UNIQUE, CHECK, ACID) — o lado CP do Teorema CAP (Aula 1): "autenticar
errado é pior que ficar fora do ar".

Regras deste arquivo:
  * É o ÚNICO lugar do sistema que escreve SQL (Repository) — auditar SQL
    Injection é ler este arquivo.
  * TODA query é parametrizada (%s + tupla). Nenhuma f-string em execute().
  * Nunca `SELECT *`: a coluna senha_hash só sai em buscar_para_login().
  * Senha nunca em texto puro: scrypt com salt (werkzeug). SHA-256 puro NÃO
    serve para senha (OWASP Password Storage Cheat Sheet).
  * Pool de conexões em vez de Singleton (apostila de patterns, Aula 2).
"""

from abc import ABC, abstractmethod
from contextlib import contextmanager

from werkzeug.security import check_password_hash, generate_password_hash

import settings

NIVEL_MIN, NIVEL_MAX = 1, 5
# Hash "fantasma": usado quando o e-mail não existe, para o tempo de resposta
# ser parecido com o de senha errada (dificulta enumeração de usuários — A07).
_HASH_FANTASMA = generate_password_hash("senha-que-ninguem-usa-0000")


class EmailDuplicado(Exception):
    """E-mail já cadastrado (UNIQUE violado)."""


class BancoIndisponivel(Exception):
    """Falha de conexão com o banco (traduzida para 503 na API, sem detalhes)."""


def validar_nivel(nivel):
    if isinstance(nivel, bool) or not isinstance(nivel, int) or not NIVEL_MIN <= nivel <= NIVEL_MAX:
        raise ValueError(f"nivel_acesso deve ser inteiro entre {NIVEL_MIN} e {NIVEL_MAX}")
    return nivel


def validar_email(email):
    email = str(email or "").strip().lower()
    if len(email) > 150 or "@" not in email or email.startswith("@") or email.endswith("@") or " " in email:
        raise ValueError("email inválido")
    return email


# ======================================================================
# Interface (o domínio fala "buscar/salvar", não SELECT/INSERT)
# ======================================================================
class RepositorioUsuarios(ABC):
    @abstractmethod
    def criar_tabela(self): ...

    @abstractmethod
    def criar(self, nome, email, senha, nivel_acesso=1) -> int: ...

    @abstractmethod
    def buscar_por_id(self, usuario_id) -> dict | None: ...

    @abstractmethod
    def buscar_por_email(self, email) -> dict | None: ...

    @abstractmethod
    def buscar_para_login(self, email) -> dict | None: ...

    @abstractmethod
    def listar(self) -> list: ...

    @abstractmethod
    def atualizar_nivel(self, usuario_id, nivel_acesso) -> bool: ...

    @abstractmethod
    def remover(self, usuario_id) -> bool: ...


# ======================================================================
# Implementação real — MySQL
# ======================================================================
SQL_CRIAR_TABELA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    nivel_acesso TINYINT NOT NULL DEFAULT 1,
    ativo BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_nivel CHECK (nivel_acesso BETWEEN 1 AND 5)
)
"""
COLUNAS_PUBLICAS = "id, nome, email, nivel_acesso, ativo, criado_em"


class RepositorioUsuariosMySQL(RepositorioUsuarios):
    def __init__(self, pool_size=5, **config):
        import mysql.connector
        from mysql.connector import pooling

        self._erro_mysql = mysql.connector.Error
        self._erro_integridade = mysql.connector.IntegrityError
        cfg = {
            "host": settings.MYSQL_HOST,
            "port": settings.MYSQL_PORTA,
            "user": settings.MYSQL_USUARIO,
            "password": settings.MYSQL_SENHA,
            "database": settings.MYSQL_BANCO,
            "connection_timeout": 5,
        }
        cfg.update(config)
        try:
            self._pool = pooling.MySQLConnectionPool(pool_name="securapy", pool_size=pool_size, **cfg)
        except mysql.connector.Error as erro:
            raise BancoIndisponivel(str(erro.errno)) from erro

    @contextmanager
    def _cursor(self):
        """Uma conexão do pool por operação; commit no sucesso, rollback no erro."""
        try:
            con = self._pool.get_connection()
        except self._erro_mysql as erro:
            raise BancoIndisponivel(str(getattr(erro, "errno", ""))) from erro
        cur = con.cursor(dictionary=True)
        try:
            yield cur
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            cur.close()
            con.close()  # devolve ao pool

    def criar_tabela(self):
        with self._cursor() as cur:
            cur.execute(SQL_CRIAR_TABELA)

    def criar(self, nome, email, senha, nivel_acesso=1):
        nome = str(nome or "").strip()[:100]
        if not nome:
            raise ValueError("nome obrigatório")
        email = validar_email(email)
        validar_nivel(nivel_acesso)
        if not senha or len(senha) < 8:
            raise ValueError("senha deve ter pelo menos 8 caracteres")
        try:
            with self._cursor() as cur:
                cur.execute(
                    "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)",
                    (nome, email, generate_password_hash(senha), nivel_acesso),
                )
                return cur.lastrowid
        except self._erro_integridade as erro:
            if getattr(erro, "errno", None) == 1062:       # ER_DUP_ENTRY
                raise EmailDuplicado(email) from None
            raise

    def buscar_por_id(self, usuario_id):
        with self._cursor() as cur:
            cur.execute(f"SELECT {COLUNAS_PUBLICAS} FROM usuarios WHERE id = %s", (usuario_id,))
            return cur.fetchone()

    def buscar_por_email(self, email):
        with self._cursor() as cur:
            cur.execute(f"SELECT {COLUNAS_PUBLICAS} FROM usuarios WHERE email = %s",
                        (str(email).strip().lower(),))
            return cur.fetchone()

    def buscar_para_login(self, email):
        """Único método que devolve senha_hash — uso exclusivo de autenticar()."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT id, nome, email, nivel_acesso, ativo, senha_hash FROM usuarios WHERE email = %s",
                (str(email).strip().lower(),),
            )
            return cur.fetchone()

    def listar(self):
        with self._cursor() as cur:
            cur.execute(f"SELECT {COLUNAS_PUBLICAS} FROM usuarios ORDER BY id")
            return cur.fetchall()

    def atualizar_nivel(self, usuario_id, nivel_acesso):
        validar_nivel(nivel_acesso)
        with self._cursor() as cur:
            cur.execute("UPDATE usuarios SET nivel_acesso = %s WHERE id = %s", (nivel_acesso, usuario_id))
            return cur.rowcount > 0

    def remover(self, usuario_id):
        with self._cursor() as cur:
            cur.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
            return cur.rowcount > 0


# ======================================================================
# Implementação em memória — testes (pytest) sem Docker/MySQL
# ======================================================================
class RepositorioUsuariosMemoria(RepositorioUsuarios):
    def __init__(self):
        self._dados = {}
        self._proximo = 1

    def criar_tabela(self):
        pass

    def criar(self, nome, email, senha, nivel_acesso=1):
        nome = str(nome or "").strip()[:100]
        if not nome:
            raise ValueError("nome obrigatório")
        email = validar_email(email)
        validar_nivel(nivel_acesso)
        if not senha or len(senha) < 8:
            raise ValueError("senha deve ter pelo menos 8 caracteres")
        if any(u["email"] == email for u in self._dados.values()):
            raise EmailDuplicado(email)
        uid = self._proximo
        self._proximo += 1
        self._dados[uid] = {"id": uid, "nome": nome, "email": email, "nivel_acesso": nivel_acesso,
                            "ativo": True, "criado_em": None, "senha_hash": generate_password_hash(senha)}
        return uid

    @staticmethod
    def _publico(u):
        return None if u is None else {k: v for k, v in u.items() if k != "senha_hash"}

    def buscar_por_id(self, usuario_id):
        return self._publico(self._dados.get(usuario_id))

    def buscar_por_email(self, email):
        email = str(email).strip().lower()
        return self._publico(next((u for u in self._dados.values() if u["email"] == email), None))

    def buscar_para_login(self, email):
        email = str(email).strip().lower()
        u = next((u for u in self._dados.values() if u["email"] == email), None)
        return dict(u) if u else None

    def listar(self):
        return [self._publico(u) for u in self._dados.values()]

    def atualizar_nivel(self, usuario_id, nivel_acesso):
        validar_nivel(nivel_acesso)
        if usuario_id not in self._dados:
            return False
        self._dados[usuario_id]["nivel_acesso"] = nivel_acesso
        return True

    def remover(self, usuario_id):
        return self._dados.pop(usuario_id, None) is not None


# ======================================================================
# Autenticação de operadores
# ======================================================================
def autenticar(repo, email, senha):
    """
    Devolve o usuário (sem hash) se email+senha conferem; senão None.
    Mesmo caminho e mesmo custo para "usuário não existe" e "senha errada":
    quem chama responde sempre o MESMO 401 genérico (anti-enumeração, A07).
    """
    registro = repo.buscar_para_login(email) if email else None
    hash_alvo = registro["senha_hash"] if registro else _HASH_FANTASMA
    senha_ok = check_password_hash(hash_alvo, senha or "")
    if not registro or not senha_ok or not registro.get("ativo", True):
        return None
    return {k: v for k, v in registro.items() if k != "senha_hash"}


def garantir_admin(repo, nome, email, senha):
    """Cria o admin inicial (nível 5) a partir do .env, se ainda não existir."""
    if not email or not senha:
        print("[AVISO] ADMIN_EMAIL/ADMIN_SENHA não definidos — nenhum admin criado.")
        return None
    if repo.buscar_por_email(email):
        return None
    try:
        return repo.criar(nome, email, senha, 5)
    except EmailDuplicado:
        return None
