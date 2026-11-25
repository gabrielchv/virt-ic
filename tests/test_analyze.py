"""Classificação de fase dos Pacotes Lógicos.

O Traço é o produto do projeto, e a lista ordenada de fases é o critério de
aceitação do PLAN.md. Estes testes fixam a única regra que decide entre
"consulta enviada ao banco" e "resposta do banco", porque o deslize ali inverte
a narrativa de cada requisição.

Rodar: `python3 -m unittest discover -s tests -v` na raiz do repositório.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "poc"))

import analyze  # noqa: E402

TCP_ACK_PSH = "0x18"


def avistamento(**campos: str) -> dict:
    """Um Avistamento com todo campo presente, como `dissecar` produz."""
    base = dict.fromkeys(analyze.FIELDS, "")
    base.update(campos)
    return base


def pg(tipo: str, *, de_cliente: bool) -> dict:
    """Segmento do Postgres, na direção pedida."""
    portas = (
        {"tcp.srcport": "40000", "tcp.dstport": analyze.PORTA_PG}
        if de_cliente
        else {"tcp.srcport": analyze.PORTA_PG, "tcp.dstport": "40000"}
    )
    return avistamento(**{"pgsql.type": tipo, "tcp.flags": TCP_ACK_PSH, **portas})


class FaseDoPostgresTests(unittest.TestCase):
    """Resposta do servidor não pode ser classificada como consulta do cliente."""

    ROTULOS_DE_RESPOSTA = [
        # Todos contêm, como substring, uma das palavras que o código antigo
        # procurava ("query", "parse", "bind") e por isso eram lidos como
        # consulta: a resposta virava o pedido.
        "Ready for query",
        "Empty query",
        "Parse completion",
        "Bind completion",
        "Command completion",
        "Row description",
        "Data row",
    ]

    def test_respostas_do_servidor_nao_sao_consultas(self):
        for rotulo in self.ROTULOS_DE_RESPOSTA:
            with self.subTest(rotulo=rotulo):
                self.assertEqual(
                    analyze.classificar(pg(rotulo, de_cliente=False)),
                    "resposta-do-banco",
                )

    ROTULOS_DE_PEDIDO = [
        # Nenhum destes contém "query"/"parse"/"bind", então o código antigo os
        # classificava como resposta mesmo sendo pedidos do cliente.
        "Describe",
        "Execute",
        "Sync",
        "Flush",
        "Close",
        "Simple query",
        "Parse",
        "Bind",
    ]

    def test_pedidos_do_cliente_sao_consultas(self):
        for rotulo in self.ROTULOS_DE_PEDIDO:
            with self.subTest(rotulo=rotulo):
                self.assertEqual(
                    analyze.classificar(pg(rotulo, de_cliente=True)),
                    "consulta-sql",
                )

    def test_varias_mensagens_num_segmento_usam_a_primeira(self):
        # `-E occurrence=a` junta as mensagens de um segmento com vírgula. Um
        # segmento que começa com resposta é resposta.
        resposta = "Command completion,Ready for query"
        self.assertEqual(analyze.classificar(pg(resposta, de_cliente=False)), "resposta-do-banco")

        pedido = "Parse,Bind,Execute,Sync"
        self.assertEqual(analyze.classificar(pg(pedido, de_cliente=True)), "consulta-sql")

    def test_sem_porta_visivel_desempata_pelo_rotulo_exato(self):
        # Depois de uma tradução que reescreve as portas, a direção não é
        # observável. A comparação precisa ser exata: "parse" é substring de
        # "parse completion", que é resposta.
        def sem_portas(tipo: str) -> dict:
            return avistamento(**{"pgsql.type": tipo, "tcp.flags": TCP_ACK_PSH})

        self.assertEqual(analyze.classificar(sem_portas("Parse")), "consulta-sql")
        self.assertEqual(analyze.classificar(sem_portas("Parse completion")), "resposta-do-banco")
        self.assertEqual(analyze.classificar(sem_portas("Bind")), "consulta-sql")
        self.assertEqual(analyze.classificar(sem_portas("Bind completion")), "resposta-do-banco")
        self.assertEqual(analyze.classificar(sem_portas("Ready for query")), "resposta-do-banco")
        self.assertEqual(analyze.classificar(sem_portas("Execute")), "consulta-sql")

    def test_autenticacao_continua_reconhecida_nas_duas_direcoes(self):
        # A fase de autenticação é nomeada pelo conteúdo, não pela direção.
        self.assertEqual(
            analyze.classificar(pg("Authentication request", de_cliente=False)),
            "autenticacao-postgres",
        )
        self.assertEqual(
            analyze.classificar(pg("Startup message", de_cliente=True)),
            "autenticacao-postgres",
        )


class FasesDeTransporteTests(unittest.TestCase):
    """A ordem das checagens importa: TCP vem antes do conteúdo da aplicação."""

    def test_syn_e_abertura_mesmo_com_carga_de_aplicacao(self):
        syn = avistamento(**{"tcp.flags": "0x02", "pgsql.type": "Startup message"})
        self.assertEqual(analyze.classificar(syn), "abertura-de-conexao")

    def test_fin_e_encerramento(self):
        for flag in ("0x01", "0x04", "0x11"):
            with self.subTest(flag=flag):
                self.assertEqual(
                    analyze.classificar(avistamento(**{"tcp.flags": flag})) == "encerramento",
                    True,
                )

    def test_dns_vem_antes_de_tudo(self):
        consulta = avistamento(**{"dns.qry.name": "db", "tcp.flags": "0x02"})
        self.assertEqual(analyze.classificar(consulta), "resolucao-de-nome")

    def test_http_reconhecido_pelas_duas_direcoes(self):
        pedido = avistamento(**{"tcp.flags": TCP_ACK_PSH, "http.request.method": "GET"})
        resposta = avistamento(**{"tcp.flags": TCP_ACK_PSH, "http.response.code": "200"})
        self.assertEqual(analyze.classificar(pedido), "requisicao-http")
        self.assertEqual(analyze.classificar(resposta), "resposta-http")

    def test_segmento_sem_conteudo_conhecido_nao_inaugura_fase(self):
        self.assertIsNone(analyze.classificar(avistamento(**{"tcp.flags": TCP_ACK_PSH})))


if __name__ == "__main__":
    unittest.main()
