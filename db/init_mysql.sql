-- Executado automaticamente pelo contêiner MySQL na PRIMEIRA subida
-- (montado em /docker-entrypoint-initdb.d). A aplicação também roda
-- CREATE TABLE IF NOT EXISTS ao iniciar, então este arquivo é só a
-- documentação do schema + garantia extra.
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    nivel_acesso TINYINT NOT NULL DEFAULT 1,
    ativo BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_nivel CHECK (nivel_acesso BETWEEN 1 AND 5)
);
