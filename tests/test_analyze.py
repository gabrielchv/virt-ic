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


class CorrelacaoTests(unittest.TestCase):
    """Um Pacote Lógico por datagrama — nem a mais, nem a menos.

    Este é o invariante que o projeto existe para ensinar: sem ele, uma
    visualização multiponto sugere que houve três pacotes onde houve um. O erro
    inverso (dois datagramas fundidos em um) apaga tráfego.
    """

    def _av(self, ponto: str, t: float, **campos: str) -> dict:
        base = {
            "ponto": ponto,
            "t": t,
            "tcp.flags": "0x10",
            "tcp.seq_raw": "100",
            "tcp.ack_raw": "200",
            "tcp.len": "0",
            "tcp.payload": "",
        }
        return avistamento(**{**base, **campos})

    def test_um_datagrama_em_tres_pontos_e_um_pacote_logico(self):
        avistamentos = [
            self._av("host-lo", 1.0),
            self._av("host-bridge", 1.001),
            self._av("web-eth0", 1.002),
        ]
        logicos = analyze.correlacionar(avistamentos)

        self.assertEqual(len(logicos), 1)
        self.assertEqual(len(logicos[0]["avistamentos"]), 3)

    def test_dois_acks_duplicados_no_mesmo_ponto_sao_dois_pacotes(self):
        # Mesmo seq/ack/len/flags e payload vazio: a chave de correlação é
        # idêntica, mas são dois segmentos distintos na rede.
        avistamentos = [self._av("web-eth0", 1.0), self._av("web-eth0", 1.004)]
        logicos = analyze.correlacionar(avistamentos)

        self.assertEqual(len(logicos), 2, "dois ACKs duplicados viraram um pacote só")
        for pacote in logicos:
            self.assertEqual(len(pacote["avistamentos"]), 1)

    def test_o_mesmo_par_observado_em_dois_pontos_continua_pareado(self):
        # Dois datagramas idênticos, cada um visto em dois pontos: dois Pacotes
        # Lógicos, cada um com dois avistamentos.
        avistamentos = [
            self._av("web-eth0", 1.0),
            self._av("db-eth0", 1.001),
            self._av("web-eth0", 1.5),
            self._av("db-eth0", 1.501),
        ]
        logicos = analyze.correlacionar(avistamentos)

        self.assertEqual(len(logicos), 2)
        self.assertEqual(sorted(len(p["avistamentos"]) for p in logicos), [2, 2])
        for pacote in logicos:
            self.assertEqual(sorted(pacote["pontos"]), ["db-eth0", "web-eth0"])

    def test_requisicao_e_resposta_icmp_nao_se_fundem(self):
        # Pedido e resposta de eco compartilham ip.id, protocolo e payload.
        pedido = avistamento(ponto="host-lo", t=1.0, **{"ip.id": "77", "ip.proto": "1", "icmp.type": "8", "data.data": "abcd"})
        resposta = avistamento(ponto="db-eth0", t=1.002, **{"ip.id": "77", "ip.proto": "1", "icmp.type": "0", "data.data": "abcd"})
        logicos = analyze.correlacionar([pedido, resposta])

        self.assertEqual(len(logicos), 2, "pedido e resposta ICMP fundidos em um pacote")

    def test_pacotes_logicos_saem_ordenados_por_tempo(self):
        avistamentos = [
            self._av("web-eth0", 5.0),
            self._av("web-eth0", 1.0),
            self._av("web-eth0", 3.0),
        ]
        t0s = [p["t0"] for p in analyze.correlacionar(avistamentos)]

        self.assertEqual(t0s, sorted(t0s))


class TabelaDeTraducaoTests(unittest.TestCase):
    """A seção que ensina onde a tradução aconteceu.

    É o ponto central do projeto, e ela pareava duas listas construídas com
    critérios diferentes (`enderecos` deduplicado por endereço, `pontos` por
    ponto) com um `zip`. Quando dois Pontos de Observação compartilham o mesmo
    endereço, as listas têm tamanhos diferentes e o deslocamento atribui cada
    endereço ao ponto errado.
    """

    def _av(self, ponto: str, t: float, src: str, dst: str, sport: int, dport: int) -> dict:
        return avistamento(
            **{
                "ponto": ponto,
                "t": t,
                "tcp.flags": TCP_ACK_PSH,
                "tcp.seq_raw": "500",
                "tcp.ack_raw": "600",
                "tcp.len": "10",
                "tcp.payload": "deadbeef",
                "ip.src": src,
                "ip.dst": dst,
                "tcp.srcport": str(sport),
                "tcp.dstport": str(dport),
            }
        )

    def _linhas_de_traducao(self, avistamentos: list[dict]) -> list[str]:
        logicos = analyze.correlacionar(avistamentos)
        episodio = {
            "tipo": "abertura-de-conexao",
            "conexao": analyze.id_conexao(avistamentos[0]),
            "pacotes": logicos,
        }
        manifesto = {"cenario": {"url": "x", "repeticoes": 1}, "pontos": []}
        texto = analyze.relatorio([episodio], logicos, avistamentos, manifesto)

        linhas, dentro = [], False
        for linha in texto.splitlines():
            if "TRADUÇÃO" in linha:
                dentro = True
                continue
            if dentro:
                if linha.strip() == "":
                    break
                linhas.append(linha.strip())
        return linhas

    def test_cada_ponto_aparece_com_o_endereco_que_ele_mesmo_v_i(self):
        # Quatro pontos, e os dois primeiros compartilham endereço: três
        # endereços distintos para quatro pontos é o caso que desalinha o zip.
        avistamentos = [
            self._av("host-lo", 1.000, "10.0.0.1", "10.0.0.1", 40000, 8000),
            self._av("host-bridge", 1.001, "10.0.0.1", "10.0.0.1", 40000, 8000),
            self._av("web-eth0", 1.002, "172.18.0.3", "172.18.0.4", 40000, 5432),
            self._av("db-eth0", 1.003, "172.18.0.3", "172.18.0.4", 40000, 5432),
        ]

        linhas = self._linhas_de_traducao(avistamentos)

        self.assertEqual(
            linhas,
            [
                "host-lo        10.0.0.1:40000 -> 10.0.0.1:8000",
                "host-bridge    10.0.0.1:40000 -> 10.0.0.1:8000",
                "web-eth0       172.18.0.3:40000 -> 172.18.0.4:5432",
                "db-eth0        172.18.0.3:40000 -> 172.18.0.4:5432",
            ],
        )

    def test_um_ponto_aparece_uma_vez_so(self):
        avistamentos = [
            self._av("web-eth0", 1.000, "172.18.0.3", "172.18.0.4", 40000, 5432),
            self._av("host-lo", 1.001, "10.0.0.1", "10.0.0.1", 40000, 8000),
        ]
        linhas = self._linhas_de_traducao(avistamentos)

        pontos = [linha.split()[0] for linha in linhas]
        self.assertEqual(pontos, ["web-eth0", "host-lo"])
