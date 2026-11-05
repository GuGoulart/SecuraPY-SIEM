"""
Central de alertas — padrão Observer (apostila de patterns, Aula 3).

Quem gera o alerta (a plataforma) não conhece quem reage a ele (servidor
TCP, arquivo, ...). O try/except por observador é o coração do padrão:
um canal quebrado não derruba os outros.
"""

import logging

log = logging.getLogger("securapy.alertas")


class CentralDeAlertas:
    def __init__(self):
        self._inscritos = []

    def inscrever(self, observador):
        self._inscritos.append(observador)
        return observador  # permite usar como decorador

    def publicar(self, alerta):
        for observador in self._inscritos:
            try:
                observador(alerta)
            except Exception as erro:
                log.warning("observador %s falhou: %s", getattr(observador, "__name__", observador),
                            type(erro).__name__)


def observador_tcp(severidades):
    """Observador que repassa ao servidor TCP do 1º semestre (broadcast_alerta)."""
    from alertas.servidor_alertas import broadcast_alerta

    def tcp(alerta):
        if alerta.get("severidade") in severidades:
            broadcast_alerta(alerta)

    return tcp


def observador_log(alerta):
    """Registra no log da aplicação os alertas críticos/altos (A09)."""
    if alerta.get("severidade") not in ("critica", "alta"):
        return
    log.info("ALERTA [%s] %s - %s", alerta.get("severidade"), alerta.get("regra"), alerta.get("ip"))
