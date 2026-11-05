# SecuraPy Platform — imagem da API (Aula 11)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependências primeiro: aproveita o cache de camadas do Docker
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Nunca rodar como root dentro do contêiner (princípio do menor privilégio)
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/var /app/saida \
    && chown -R appuser:appuser /app/var /app/saida
USER appuser

EXPOSE 5000 9999

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=4).status == 200 else 1)"

# waitress: servidor WSGI de produção, 1 processo com várias threads
# (1 processo só = 1 servidor TCP de alertas na porta 9999, sem conflito)
CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "--threads=8", "--call", "api.app:create_app"]
