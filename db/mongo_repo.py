"""
Repositório de EVENTOS e ALERTAS no MongoDB (Aulas 1–3; patterns Aula 6).

Por que MongoDB aqui: volume alto, schema flexível (cada fonte de log tem
campos diferentes) e escrita rápida — o lado AP/CP discutido na Aula 1.

Toda consulta é montada com dicionários (nunca concatenando string), e os
filtros que vêm da API passam por whitelist antes de chegar aqui.
"""

from urllib.parse import quote_plus

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import BulkWriteError, DuplicateKeyError

import settings
from core.contrato import agora, alerta_para_documento, evento_para_documento

CODIGO_DUPLICADO = 11000
ORDEM_PRIORIDADE = [("ml_score", DESCENDING), ("pontuacao", DESCENDING),
                    ("timestamp", DESCENDING), ("_id", ASCENDING)]


def montar_uri():
    """Monta a URI escapando usuário/senha (senha com @ ou : quebraria a URI)."""
    if settings.MONGO_USUARIO:
        cred = f"{quote_plus(settings.MONGO_USUARIO)}:{quote_plus(settings.MONGO_SENHA)}@"
        return f"mongodb://{cred}{settings.MONGO_HOST}:{settings.MONGO_PORTA}/?authSource=admin"
    return f"mongodb://{settings.MONGO_HOST}:{settings.MONGO_PORTA}/"


def conectar(uri=None, banco=None, timeout_ms=3000):
    """Conecta e confirma com ping (Aula 2.2). Lança PyMongoError se não conseguir."""
    cliente = MongoClient(uri or montar_uri(), serverSelectionTimeoutMS=timeout_ms)
    cliente.admin.command("ping")
    return cliente[banco or settings.MONGO_BANCO]


class RepositorioMongo:
    def __init__(self, db):
        self.db = db
        self.eventos = db["eventos"]
        self.alertas = db["alertas"]

    # ------------------------------------------------------------------ índices
    def criar_indices(self, retencao_dias=None):
        """Índices da Aula 2.4. TTL sobre `ingerido_em` — NUNCA sobre o timestamp do
        log: os logs de teste são de 2025 e seriam apagados em ~60 s."""
        dias = retencao_dias or settings.RETENCAO_DIAS
        self.eventos.create_index("hash", unique=True)
        self.eventos.create_index("ip")
        self.eventos.create_index([("timestamp", DESCENDING)])
        self.eventos.create_index([("fonte", ASCENDING), ("timestamp", DESCENDING)])
        self.eventos.create_index("ingerido_em", expireAfterSeconds=dias * 86400)
        self.alertas.create_index("hash", unique=True)
        self.alertas.create_index("ip")
        self.alertas.create_index([("severidade", ASCENDING), ("timestamp", DESCENDING)])

    # ------------------------------------------------------------------ escrita
    @staticmethod
    def _inserir_ignorando_duplicados(colecao, documentos):
        """insert_many(ordered=False): duplicados (mesmo hash) são ignorados, o resto entra.
        Isso torna a ingestão idempotente — rodar a análise 2x não duplica os 58 eventos."""
        if not documentos:
            return 0
        try:
            return len(colecao.insert_many(documentos, ordered=False).inserted_ids)
        except BulkWriteError as erro:
            detalhes = erro.details or {}
            outros = [e for e in detalhes.get("writeErrors", []) if e.get("code") != CODIGO_DUPLICADO]
            if outros:
                raise
            return detalhes.get("nInserted", 0)

    def salvar_eventos(self, eventos):
        """Recebe eventos do coletor (1º sem). Retorna quantos eram NOVOS."""
        docs = [evento_para_documento(e) for e in eventos]
        return self._inserir_ignorando_duplicados(self.eventos, docs)

    def salvar_alertas(self, alertas, origem="regra"):
        docs = [alerta_para_documento(a, origem) for a in alertas]
        return self._inserir_ignorando_duplicados(self.alertas, docs)

    def salvar_alertas_detector(self, alertas):
        """Alertas do detector/ML: upsert — reanálise atualiza score e severidade."""
        novos = 0
        for alerta in alertas:
            doc = alerta_para_documento(alerta, origem="detector")
            criado_em = doc.pop("criado_em")
            res = self.alertas.update_one(
                {"hash": doc["hash"]},
                {"$set": {**doc, "atualizado_em": agora()}, "$setOnInsert": {"criado_em": criado_em}},
                upsert=True,
            )
            novos += 1 if res.upserted_id is not None else 0
        return novos

    def criar_alerta(self, alerta):
        """Alerta manual vindo do POST /api/alertas (já validado na API)."""
        doc = alerta_para_documento(alerta, origem="manual")
        try:
            res = self.alertas.insert_one(doc)
        except DuplicateKeyError:            # praticamente impossível (uuid), mas tratado
            raise ValueError("alerta duplicado")
        doc["_id"] = res.inserted_id
        return doc

    # ------------------------------------------------------------------ leitura
    @staticmethod
    def _filtro(fonte=None, tipo=None, ip=None, desde=None, ate=None, severidade=None, origem=None):
        """Monta o filtro só com o que foi informado (Exercício 2.3 da apostila)."""
        filtro = {}
        if fonte:
            filtro["fonte"] = fonte
        if tipo:
            filtro["tipo"] = tipo
        if ip:
            filtro["ip"] = ip
        if severidade:
            filtro["severidade"] = severidade
        if origem:
            filtro["origem"] = origem
        if desde or ate:
            filtro["timestamp"] = {}
            if desde:
                filtro["timestamp"]["$gte"] = desde
            if ate:
                filtro["timestamp"]["$lte"] = ate
        return filtro

    def _paginar(self, colecao, filtro, pagina, tamanho, ordem):
        total = colecao.count_documents(filtro)
        cursor = (colecao.find(filtro, {"hash": 0})
                  .sort(ordem)
                  .skip((pagina - 1) * tamanho)
                  .limit(tamanho))
        return list(cursor), total

    def buscar_eventos(self, pagina=1, tamanho=20, **filtros):
        return self._paginar(self.eventos, self._filtro(**filtros), pagina, tamanho,
                             [("timestamp", DESCENDING), ("_id", ASCENDING)])

    def buscar_alertas(self, pagina=1, tamanho=20, **filtros):
        # Prioridade: score de ML do IP (Módulo C) > pontuação da regra > mais recente
        return self._paginar(self.alertas, self._filtro(**filtros), pagina, tamanho, ORDEM_PRIORIDADE)

    def obter_alerta(self, alerta_id):
        """id malformado -> ValueError (a API traduz em 400)."""
        try:
            oid = ObjectId(alerta_id)
        except (InvalidId, TypeError):
            raise ValueError("id inválido")
        return self.alertas.find_one({"_id": oid}, {"hash": 0})

    def eventos_do_ip(self, ip, limite=500):
        return list(self.eventos.find({"ip": ip}, {"hash": 0}).sort("timestamp", ASCENDING).limit(limite))

    def alertas_do_ip(self, ip, limite=200):
        return list(self.alertas.find({"ip": ip}, {"hash": 0}).sort(ORDEM_PRIORIDADE).limit(limite))

    def eventos_dos_ips(self, ips, limite=20000):
        return list(self.eventos.find({"ip": {"$in": list(ips)}}, {"hash": 0}).limit(limite))

    def todos_eventos(self, limite=50000):
        return list(self.eventos.find({}, {"hash": 0, "_id": 0}).limit(limite))

    def todos_alertas(self, limite=50000):
        return list(self.alertas.find({}, {"hash": 0}).sort(ORDEM_PRIORIDADE).limit(limite))

    def alertas_recentes(self, limite=10):
        return list(self.alertas.find({}, {"hash": 0}).sort([("criado_em", DESCENDING), ("_id", DESCENDING)])
                    .limit(limite))

    def atualizar_score_ip(self, ip, score):
        """Grava o score de ML em todos os alertas do IP (usado para ordenar)."""
        return self.alertas.update_many({"ip": ip}, {"$set": {"ml_score": score}}).modified_count

    # ------------------------------------------------------------------ agregação
    def top_ips(self, n=5):
        """Top N IPs por número de eventos (agregação no banco, não em laço Python)."""
        pipeline = [
            {"$group": {"_id": "$ip", "total": {"$sum": 1},
                        "fontes": {"$addToSet": "$fonte"}}},
            {"$sort": {"total": -1, "_id": 1}},
            {"$limit": n},
        ]
        return [{"ip": d["_id"], "eventos": d["total"], "fontes": sorted(d["fontes"])}
                for d in self.eventos.aggregate(pipeline)]

    def top_ips_falhas(self, n=5):
        pipeline = [
            {"$match": {"tipo": "FAIL"}},
            {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
            {"$sort": {"total": -1, "_id": 1}},
            {"$limit": n},
        ]
        return [{"ip": d["_id"], "falhas": d["total"]} for d in self.eventos.aggregate(pipeline)]

    def contagem_por_severidade(self):
        pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}]
        return {d["_id"]: d["total"] for d in self.alertas.aggregate(pipeline)}

    def contagem_por_fonte(self):
        pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}]
        return {d["_id"]: d["total"] for d in self.eventos.aggregate(pipeline)}

    def totais(self):
        return {"eventos": self.eventos.count_documents({}),
                "alertas": self.alertas.count_documents({})}
