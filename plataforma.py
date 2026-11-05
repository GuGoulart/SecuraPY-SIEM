"""
Fachada da plataforma (patterns, Aula 5 — Facade).

Esconde a orquestração: núcleo do 1º sem (coletor -> regras -> detector)
+ correlação temporal + persistência + ML + publicação de alertas.
API, dashboard e script de migração usam só estes métodos:

    analisar_pasta() / analisar_arquivo(nome) / analisar_eventos(lista)
    perfil_ip(ip)  /  resumo_dashboard()  /  relatorio_completo()
"""

import ipaddress
import logging
import re
from pathlib import Path

import settings
from core.blacklist import carregar_blacklist
from core.coletor import carregar_log, carregar_todos_os_logs
from core.contrato import PESO_SEVERIDADE, agora, documento_para_evento, normalizar_severidade, para_json
from core.correlacao import correlacao_para_alertas, detectar_brute_force_janela
from core.detector import detectar_brute_force, detectar_port_scan, gerar_resumo_ameacas, verificar_blacklist
from core.enriquecimento import consultar_ip
from core.regras import aplicar_regras, carregar_regras
from ia.assistente import classificar_evento, classificar_por_regras
from ml.anomalias import detectar_anomalias
from ml.classificar import pontuar
from ml.features import extrair_features

log = logging.getLogger("securapy.plataforma")
NOME_LOG_VALIDO = re.compile(r"^[A-Za-z0-9_.-]{1,64}\.log$")


class ArquivoInvalido(ValueError):
    """Nome/caminho de log fora da pasta permitida (anti path traversal)."""


def _fonte_do_nome(nome):
    """Mesma heurística do carregar_todos_os_logs do 1º semestre."""
    for fonte in ("auth", "firewall", "web"):
        if fonte in nome:
            return fonte
    return None


class PlataformaSecuraPy:
    def __init__(self, repo, modelo=None, central=None, regras=None, blacklist=None, pasta_logs=None):
        self.repo = repo
        self.modelo = modelo
        self.central = central
        self.regras = regras if regras is not None else carregar_regras(str(settings.ARQUIVO_REGRAS))
        self.blacklist = blacklist if blacklist is not None else carregar_blacklist(settings.ARQUIVO_BLACKLIST)
        self.pasta_logs = Path(pasta_logs or settings.PASTA_LOGS).resolve()
        self.cache_enriquecimento = {}

    # ================================================================ análise
    def resolver_arquivo(self, nome):
        """Só aceita um NOME de arquivo .log dentro de PASTA_LOGS (nada de ../../etc/passwd)."""
        nome = str(nome or "")
        if not NOME_LOG_VALIDO.fullmatch(nome):
            raise ArquivoInvalido("nome de arquivo inválido (use apenas o nome, ex.: auth.log)")
        caminho = (self.pasta_logs / nome).resolve()
        if caminho.parent != self.pasta_logs:
            raise ArquivoInvalido("arquivo fora da pasta de logs")
        if not caminho.is_file():
            raise FileNotFoundError(nome)
        fonte = _fonte_do_nome(nome)
        if fonte is None:
            raise ArquivoInvalido("não foi possível identificar a fonte (auth/firewall/web) pelo nome")
        return caminho, fonte

    def analisar_pasta(self):
        return self.analisar_eventos(carregar_todos_os_logs(str(self.pasta_logs)))

    def analisar_arquivo(self, nome):
        caminho, fonte = self.resolver_arquivo(nome)
        return self.analisar_eventos(carregar_log(str(caminho), fonte))

    def analisar_eventos(self, eventos):
        # 1-3. Núcleo do 1º semestre, sem alteração de comportamento
        alertas_regras = aplicar_regras(eventos, self.regras)
        bf = detectar_brute_force(eventos)
        ps = detectar_port_scan(eventos)
        bl = verificar_blacklist(eventos, self.blacklist)
        ameacas = gerar_resumo_ameacas(bf, ps, bl)
        # Bônus: correlação temporal
        alertas_correlacao = correlacao_para_alertas(detectar_brute_force_janela(eventos))

        # 4. Persistência dos eventos (idempotente)
        eventos_novos = self.repo.salvar_eventos(eventos)

        # 5. ML: features com TODO o histórico dos IPs envolvidos
        ips_lote = {e["ip"] for e in eventos}
        scores = self._scores(ips_lote)

        # 6. Ameaças do detector viram alertas (com score de ML)
        ultimo_ts = {}
        for e in eventos:
            ultimo_ts[e["ip"]] = max(ultimo_ts.get(e["ip"], ""), e["timestamp"])
        alertas_detector = []
        for a in ameacas:
            ml = scores.get(a["ip"])
            alertas_detector.append({
                "timestamp": ultimo_ts.get(a["ip"]),
                "regra": "Detector: " + " + ".join(a["deteccoes"]),
                "regra_id": "DET-" + "-".join(a["deteccoes"]),
                "severidade": a["severidade"],
                "pontuacao": a["pontuacao"],
                "ip": a["ip"],
                "descricao": "Detecções correlacionadas: " + ", ".join(a["deteccoes"]),
                "deteccoes": a["deteccoes"],
                "detalhes_deteccao": para_json(a["detalhes"]),
                **({"ml": ml} if ml else {}),
            })

        # 7. Persistência dos alertas
        novos_alertas = (self.repo.salvar_alertas(alertas_regras, origem="regra")
                         + self.repo.salvar_alertas(alertas_correlacao, origem="correlacao")
                         + self.repo.salvar_alertas_detector(alertas_detector))
        for ip, ml in scores.items():
            self.repo.atualizar_score_ip(ip, ml["score"])

        # 8. Publicação em tempo real (Observer -> servidor TCP)
        todos = alertas_regras + alertas_correlacao + alertas_detector
        por_severidade = {}
        for alerta in todos:
            sev = normalizar_severidade(alerta["severidade"]) or "info"
            por_severidade[sev] = por_severidade.get(sev, 0) + 1
            if self.central is not None:
                self.central.publicar({**alerta, "severidade": sev})

        por_fonte = {}
        for e in eventos:
            por_fonte[e["fonte"]] = por_fonte.get(e["fonte"], 0) + 1

        ranking = sorted(
            ({"ip": a["ip"], "deteccoes": a["deteccoes"],
              "severidade": normalizar_severidade(a["severidade"]),
              "pontuacao": a["pontuacao"], "ml": scores.get(a["ip"])} for a in ameacas),
            key=lambda x: ((x["ml"] or {}).get("score", 0), x["pontuacao"]), reverse=True,
        )
        return {
            "analisado_em": agora().strftime("%Y-%m-%d %H:%M:%S"),
            "eventos": {"recebidos": len(eventos), "novos": eventos_novos, "por_fonte": por_fonte},
            "alertas": {"gerados": len(todos), "novos": novos_alertas, "por_severidade": por_severidade},
            "ameacas": ranking,
            "modelo_ml": "ativo" if self.modelo is not None else "indisponivel",
        }

    # ================================================================ ML
    def _features(self, ips=None):
        docs = self.repo.eventos_dos_ips(ips) if ips is not None else self.repo.todos_eventos()
        return extrair_features([documento_para_evento(d) for d in docs], self.blacklist)

    def _scores(self, ips):
        if self.modelo is None or not ips:
            return {}
        try:
            return pontuar(self.modelo, self._features(ips))
        except Exception as erro:  # modelo incompatível não derruba a análise
            log.error("falha ao pontuar com ML: %s", type(erro).__name__)
            return {}

    # ================================================================ consultas
    def perfil_ip(self, ip, enriquecer=True):
        ip = str(ipaddress.ip_address(ip))  # ValueError -> 400 na API
        eventos = self.repo.eventos_do_ip(ip)
        alertas = self.repo.alertas_do_ip(ip)
        feats_todos = self._features()
        ml = pontuar(self.modelo, {ip: feats_todos[ip]}).get(ip) if (self.modelo and ip in feats_todos) else None
        anomalia = detectar_anomalias(feats_todos).get(ip) if feats_todos else None
        geo = consultar_ip(ip, self.cache_enriquecimento) if enriquecer else None

        return {
            "ip": ip,
            "total_eventos": len(eventos),
            "total_alertas": len(alertas),
            "eventos": para_json(eventos),
            "alertas": para_json(alertas),
            "enriquecimento": geo,
            "ml": ml,
            "anomalia": anomalia,
            "assistente": self._explicar_ip(ip, eventos, alertas, feats_todos.get(ip)) if eventos else None,
        }

    def _explicar_ip(self, ip, eventos, alertas, feats):
        """Monta um resumo do IP + evento mais grave e pede a explicação ao assistente."""
        pior = max(eventos, key=lambda d: ["NORMAL", "SUSPEITO", "CRITICO"].index(
            classificar_por_regras(d.get("linha_original", ""))[0]))
        sev_max = max((a.get("severidade", "info") for a in alertas),
                      key=lambda s: PESO_SEVERIDADE.get(s, 0), default="info")
        f = feats or {}
        resumo = (f"Resumo do IP {ip}: falhas_login={f.get('falhas_login', 0)} "
                  f"portas_bloqueadas={f.get('portas_distintas', 0)} "
                  f"blacklist={'sim' if f.get('na_blacklist') else 'nao'} erros_web={f.get('web_erros', 0)} "
                  f"severidade_max={sev_max}. Evento mais grave: {pior.get('linha_original', '')}")
        return classificar_evento(resumo)

    def resumo_dashboard(self):
        top = self.repo.top_ips(10)
        feats_todos = self._features()
        scores = pontuar(self.modelo, {t["ip"]: feats_todos[t["ip"]] for t in top if t["ip"] in feats_todos}) \
            if self.modelo else {}
        anomalias = detectar_anomalias(feats_todos) if feats_todos else {}
        for t in top:
            t["ml"] = scores.get(t["ip"])
            t["anomalia"] = (anomalias.get(t["ip"]) or {}).get("anomalia", False)
        top.sort(key=lambda t: ((t["ml"] or {}).get("score", 0), t["eventos"]), reverse=True)
        sev = self.repo.contagem_por_severidade()
        return {
            "totais": self.repo.totais(),
            "eventos_por_fonte": self.repo.contagem_por_fonte(),
            "alertas_por_severidade": {s: sev.get(s, 0) for s in ("critica", "alta", "media", "baixa", "info")},
            "top_ips": top,
            "alertas_recentes": para_json(self.repo.alertas_recentes(10)),
        }

    def relatorio_completo(self):
        """Deliverable 4: JSON exportado pela plataforma com os dados de teste."""
        resumo = self.resumo_dashboard()
        return {
            "gerado_em": agora().strftime("%Y-%m-%d %H:%M:%S"),
            "plataforma": "SecuraPy Platform",
            **resumo,
            "alertas": para_json(self.repo.todos_alertas()),
            "top_ips_falhas_login": self.repo.top_ips_falhas(5),
        }
