#!/usr/bin/env python3
"""Transforma um Traço multiponto em Episódios explicados.

Três etapas:
  1. dissecação  - cada pcap vira uma lista de Avistamentos (tshark)
  2. correlação  - Avistamentos do mesmo datagrama viram um Pacote Lógico
  3. segmentação - Pacotes Lógicos viram Episódios, cada um com explicação

A correlação é o ponto delicado: entre Pontos de Observação o endereço IP e a
porta mudam (tradução feita pelo runtime), então não servem de identidade. Já o
número de sequência TCP, o campo de identificação do IP e o payload atravessam a
tradução intactos - é sobre eles que a chave é construída.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

FIELDS = [
    "frame.number", "frame.time_epoch",
    "ip.src", "ip.dst", "ip.id", "ip.proto",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw",
    "tcp.len", "tcp.flags", "tcp.payload",
    "udp.srcport", "udp.dstport", "udp.length", "data.data",
    "dns.id", "dns.qry.name", "dns.flags.response", "dns.a",
    "http.request.method", "http.request.uri", "http.response.code",
    "pgsql.type",
]

# Quando o mesmo Pacote Lógico é visto em vários lugares, este é o Ponto de
# Observação cuja visão tratamos como canônica ao nomear a conexão. Preferimos a
# visão de dentro do container: é a que a aplicação realmente enxerga.
PRIORIDADE_PONTOS = ["web-eth0", "db-eth0", "host-bridge", "web-lo", "host-lo"]

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10

EXPLICACOES = {
    "resolucao-de-nome": (
        "Resolução de nome",
        "A aplicação pediu para abrir conexão com o host chamado 'db'. Esse nome "
        "não existe para a rede - só endereços IP existem. Antes de qualquer "
        "byte de dado trafegar, o container pergunta a um servidor de nomes qual "
        "é o endereço de 'db'. Esse servidor é fornecido pelo próprio runtime de "
        "container e vive num endereço de loopback dentro do container, e é por "
        "isso que essa conversa não aparece na bridge: ela nunca sai do "
        "namespace.",
    ),
    "abertura-de-conexao": (
        "Abertura de conexão (aperto de mão de três vias)",
        "Antes de trocar dados, os dois lados combinam que a conversa começou e a "
        "partir de que número cada um vai contar seus bytes. Quem inicia manda um "
        "pacote SYN com seu número inicial; quem recebe responde SYN+ACK, "
        "confirmando o número do outro e anunciando o seu; quem iniciou confirma "
        "com um ACK. Só depois disso existe uma conexão.",
    ),
    "requisicao-http": (
        "Requisição HTTP",
        "O cliente enviou a linha de requisição e os cabeçalhos. Repare que este "
        "é o primeiro momento em que trafega algo que um humano lê - tudo antes "
        "foi negociação da própria rede.",
    ),
    "autenticacao-postgres": (
        "Autenticação no banco",
        "A conexão TCP já existe, mas o banco ainda não sabe quem está falando. O "
        "cliente envia uma mensagem de início declarando usuário e base de dados; "
        "o servidor responde exigindo uma credencial; o cliente a envia; o "
        "servidor confirma e avisa que está pronto para receber comandos. Nada "
        "disso é SQL ainda.",
    ),
    "consulta-sql": (
        "Consulta enviada ao banco",
        "Agora sim o texto do comando SQL atravessa a rede, dentro de uma mensagem "
        "do protocolo do banco. O SQL não viaja sozinho: ele é o conteúdo de um "
        "envelope que diz 'isto é uma consulta'.",
    ),
    "resposta-do-banco": (
        "Resposta do banco",
        "O banco responde em partes: primeiro a descrição das colunas, depois uma "
        "mensagem por linha de resultado, depois um aviso de que o comando "
        "terminou, e por fim um aviso de que está pronto para o próximo. O "
        "resultado não vem como um bloco único.",
    ),
    "resposta-http": (
        "Resposta HTTP",
        "O servidor web devolve o código de estado, os cabeçalhos e o corpo. Este "
        "corpo é o que o usuário final vê - e ele só existe porque toda a conversa "
        "com o banco já aconteceu antes.",
    ),
    "encerramento": (
        "Encerramento da conexão",
        "Cada lado avisa que não tem mais nada a enviar e espera a confirmação do "
        "outro. Uma conexão TCP fecha em duas metades independentes, e não de uma "
        "vez só.",
    ),
    "continuacao": (
        "Continuação da conversa",
        "Pacotes de confirmação e de continuação de dados que não abrem uma fase "
        "nova - sustentam a fase que já estava em andamento.",
    ),
}


def dissecar(caminho, rotulo):
    """Roda o dissecador sobre um pcap e devolve os Avistamentos daquele ponto."""
    cmd = [
        "tshark", "-r", str(caminho), "-n",
        "-d", "tcp.port==8000,http",   # o web escuta em 8000, fora da lista padrão
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
    ]
    for campo in FIELDS:
        cmd += ["-e", campo]
    saida = subprocess.run(cmd, capture_output=True, text=True)
    if saida.returncode != 0:
        raise SystemExit(f"tshark falhou em {caminho}:\n{saida.stderr.strip()}")

    avistamentos = []
    for linha in saida.stdout.splitlines():
        partes = linha.split("\t")
        partes += [""] * (len(FIELDS) - len(partes))
        campo = dict(zip(FIELDS, partes))
        campo["ponto"] = rotulo
        campo["t"] = float(campo["frame.time_epoch"] or 0)
        avistamentos.append(campo)
    return avistamentos


def md5(texto):
    return hashlib.md5((texto or "").encode()).hexdigest()[:12]


def chave_correlacao(a):
    """Identidade do datagrama, construída só com campos que a tradução preserva.

    A tradução de endereços reescreve IP e porta e recalcula os checksums, mas
    não toca no número de sequência TCP, no identificador do IP nem no payload.
    """
    if a["tcp.seq_raw"]:
        return ("tcp", a["tcp.seq_raw"], a["tcp.ack_raw"], a["tcp.len"],
                a["tcp.flags"], md5(a["tcp.payload"]))
    if a["udp.length"]:
        return ("udp", a["ip.id"], a["udp.length"], md5(a["data.data"]))
    return ("outro", a["ip.id"], a["ip.proto"], md5(a["data.data"]))


def endereco(a):
    porta = a["tcp.srcport"] or a["udp.srcport"] or ""
    destino = a["tcp.dstport"] or a["udp.dstport"] or ""
    return f"{a['ip.src']}:{porta} -> {a['ip.dst']}:{destino}"


def correlacionar(avistamentos):
    """Agrupa Avistamentos em Pacotes Lógicos."""
    grupos = defaultdict(list)
    for a in avistamentos:
        grupos[chave_correlacao(a)].append(a)

    logicos = []
    for chave, membros in grupos.items():
        membros.sort(key=lambda a: a["t"])
        enderecos = []
        for a in membros:
            e = endereco(a)
            if e not in enderecos:
                enderecos.append(e)
        logicos.append({
            "chave": chave,
            "avistamentos": membros,
            "t0": membros[0]["t"],
            "pontos": [a["ponto"] for a in membros],
            "enderecos": enderecos,
            "traduzido": len(enderecos) > 1,
        })
    logicos.sort(key=lambda p: p["t0"])
    return logicos


def canonico(pacote):
    """O Avistamento cuja visão usamos para nomear a conexão."""
    por_ponto = {a["ponto"]: a for a in pacote["avistamentos"]}
    for ponto in PRIORIDADE_PONTOS:
        if ponto in por_ponto:
            return por_ponto[ponto]
    return pacote["avistamentos"][0]


def id_conexao(a):
    if a["tcp.srcport"]:
        lados = sorted([f"{a['ip.src']}:{a['tcp.srcport']}",
                        f"{a['ip.dst']}:{a['tcp.dstport']}"])
        return ("tcp", lados[0], lados[1])
    return ("udp", "resolucao-de-nome")


PORTA_PG = "5432"

# Rótulos que o tshark usa para mensagens iniciadas pelo **cliente**. Usado só
# como desempate quando a porta do Postgres não está visível no avistamento
# (tradução de endereço/porta). Comparação exata: "parse" é substring de
# "parse completion", que é resposta do servidor.
MENSAGENS_DO_CLIENTE = {
    "simple query",
    "parse",
    "bind",
    "execute",
    "describe",
    "close",
    "sync",
    "flush",
    "terminate",
    "password",
    "startup message",
    "function call",
    "copy data",
    "copy done",
    "copy fail",
}


def _eh_mensagem_do_cliente(tipos: str) -> bool:
    """Se a primeira mensagem do segmento foi enviada pelo cliente."""
    primeira = tipos.split(",")[0].strip().lower()
    return primeira in MENSAGENS_DO_CLIENTE


def classificar(a):
    """Que fase da conversa este Pacote Lógico inaugura, se alguma."""
    if a["dns.qry.name"]:
        return "resolucao-de-nome"

    flags = int(a["tcp.flags"], 16) if a["tcp.flags"] else 0
    if flags & TCP_SYN:
        return "abertura-de-conexao"
    if flags & (TCP_FIN | TCP_RST):
        return "encerramento"

    tipos = a["pgsql.type"]
    if tipos:
        baixo = tipos.lower()
        if any(t in baixo for t in ("startup", "authentication", "password")):
            return "autenticacao-postgres"

        # A direção decide, não o rótulo.
        #
        # `pgsql.type` é uma string legível (FT_STRING), e vários rótulos de
        # **resposta do servidor** contêm as palavras que o código antigo
        # procurava: "Ready for query" e "Empty query" contêm "query";
        # "Parse completion" contém "parse"; "Bind completion" contém "bind".
        # Testar substring classificava respostas como consulta. No sentido
        # oposto, "Describe", "Execute" e "Sync" não contêm nenhuma das três e
        # caíam em "resposta-do-banco", apesar de serem pedidos do cliente.
        # Como o psycopg usa o protocolo estendido, isso acontecia em toda
        # requisição e invertia a narrativa das fases.
        if a["tcp.dstport"] == PORTA_PG:
            return "consulta-sql"
        if a["tcp.srcport"] == PORTA_PG:
            return "resposta-do-banco"

        # Porta não visível: desempata pelo nome exato da mensagem.
        if _eh_mensagem_do_cliente(tipos):
            return "consulta-sql"
        return "resposta-do-banco"

    if a["http.request.method"]:
        return "requisicao-http"
    if a["http.response.code"]:
        return "resposta-http"
    return None


def segmentar(logicos):
    """Quebra a sequência de Pacotes Lógicos em Episódios, por conexão."""
    episodios = []
    atual_por_conexao = {}

    for pacote in logicos:
        a = canonico(pacote)
        conexao = id_conexao(a)
        tipo = classificar(a)

        corrente = atual_por_conexao.get(conexao)
        if tipo is None:
            tipo = corrente["tipo"] if corrente else "continuacao"

        if corrente is None or corrente["tipo"] != tipo:
            corrente = {"tipo": tipo, "conexao": conexao, "pacotes": [],
                        "t0": pacote["t0"]}
            episodios.append(corrente)
            atual_por_conexao[conexao] = corrente

        corrente["pacotes"].append(pacote)

    return episodios


def rotulo_conexao(conexao, episodio):
    if conexao[0] == "udp":
        return "resolução de nome (dentro do container web)"
    a = canonico(episodio["pacotes"][0])
    porta_destino = a["tcp.dstport"] or a["tcp.srcport"]
    nomes = {"5432": "web -> db", "8000": "cliente -> web", "8080": "cliente -> web"}
    return nomes.get(porta_destino, f"{conexao[1]} <-> {conexao[2]}")


def relatorio(episodios, logicos, avistamentos, manifesto):
    linhas = []
    add = linhas.append

    add("=" * 78)
    add("TRAÇO ANALISADO")
    add("=" * 78)
    add(f"Cenário          : {manifesto['cenario']['url']} "
        f"({manifesto['cenario']['repeticoes']}x)")
    add(f"Avistamentos     : {len(avistamentos)}")
    add(f"Pacotes Lógicos  : {len(logicos)}")
    traduzidos = [p for p in logicos if p["traduzido"]]
    add(f"Sofreram tradução: {len(traduzidos)}")
    multiponto = [p for p in logicos if len(set(p["pontos"])) > 1]
    add(f"Vistos em mais de um ponto: {len(multiponto)}")
    add("")
    add("Pontos de Observação deste Traço:")
    for p in manifesto["pontos"]:
        vistos = sum(1 for a in avistamentos if a["ponto"] == p["label"])
        add(f"  {p['label']:14s} {p['namespace']:12s} {p['iface']:10s} "
            f"{vistos:4d} avistamentos")
    add("")

    for i, ep in enumerate(episodios, 1):
        titulo, texto = EXPLICACOES[ep["tipo"]]
        add("-" * 78)
        add(f"EPISÓDIO {i}: {titulo}")
        add(f"conexão: {rotulo_conexao(ep['conexao'], ep)}   "
            f"pacotes lógicos: {len(ep['pacotes'])}")
        add("-" * 78)
        for paragrafo in _quebrar(texto, 76):
            add(paragrafo)
        add("")
        for pacote in ep["pacotes"]:
            a = canonico(pacote)
            resumo = _resumo(a)
            pontos = ",".join(dict.fromkeys(pacote["pontos"]))
            add(f"  [{pacote['t0']:.6f}] {resumo}")
            add(f"      visto em: {pontos}")
            if pacote["traduzido"]:
                add("      TRADUÇÃO - o mesmo pacote, endereços diferentes:")
                for e, ponto in zip(pacote["enderecos"],
                                    dict.fromkeys(pacote["pontos"])):
                    add(f"        {ponto:14s} {e}")
        add("")

    return "\n".join(linhas)


def _resumo(a):
    if a["dns.qry.name"]:
        direcao = "resposta" if a["dns.flags.response"] == "1" else "pergunta"
        extra = f" -> {a['dns.a']}" if a["dns.a"] else ""
        return f"DNS {direcao} '{a['dns.qry.name']}'{extra}"
    flags = int(a["tcp.flags"], 16) if a["tcp.flags"] else 0
    nomes = [n for bit, n in ((TCP_SYN, "SYN"), (TCP_ACK, "ACK"),
                              (TCP_FIN, "FIN"), (TCP_RST, "RST")) if flags & bit]
    partes = ["TCP " + "+".join(nomes) if nomes else "TCP"]
    if a["tcp.len"] and a["tcp.len"] != "0":
        partes.append(f"{a['tcp.len']} bytes")
    if a["pgsql.type"]:
        partes.append(f"postgres: {a['pgsql.type']}")
    if a["http.request.method"]:
        partes.append(f"HTTP {a['http.request.method']} {a['http.request.uri']}")
    if a["http.response.code"]:
        partes.append(f"HTTP {a['http.response.code']}")
    return "  ".join(partes)


def _quebrar(texto, largura):
    palavras, linha, saida = texto.split(), "", []
    for p in palavras:
        if len(linha) + len(p) + 1 > largura:
            saida.append(linha)
            linha = p
        else:
            linha = f"{linha} {p}".strip()
    if linha:
        saida.append(linha)
    return saida


def para_json(episodios, logicos, avistamentos, manifesto):
    """Modelo semântico cru, para uma futura visualização consumir."""
    return {
        "cenario": manifesto["cenario"],
        "pontos": manifesto["pontos"],
        "estatisticas": {
            "avistamentos": len(avistamentos),
            "pacotes_logicos": len(logicos),
            "traduzidos": sum(1 for p in logicos if p["traduzido"]),
            "multiponto": sum(1 for p in logicos if len(set(p["pontos"])) > 1),
        },
        "episodios": [
            {
                "tipo": ep["tipo"],
                "titulo": EXPLICACOES[ep["tipo"]][0],
                "explicacao": EXPLICACOES[ep["tipo"]][1],
                "conexao": rotulo_conexao(ep["conexao"], ep),
                "t0": ep["t0"],
                "pacotes": [
                    {
                        "t0": p["t0"],
                        "resumo": _resumo(canonico(p)),
                        "traduzido": p["traduzido"],
                        "avistamentos": [
                            {"ponto": a["ponto"], "t": a["t"],
                             "endereco": endereco(a)}
                            for a in p["avistamentos"]
                        ],
                    }
                    for p in ep["pacotes"]
                ],
            }
            for ep in episodios
        ],
    }


def main():
    ap = argparse.ArgumentParser(description="analisa um Traço multiponto")
    ap.add_argument("--traco", default="traces/ultimo")
    args = ap.parse_args()

    if not shutil.which("tshark"):
        raise SystemExit("tshark ausente. Instale com: sudo apt install tshark")

    diretorio = Path(args.traco)
    manifesto = json.loads((diretorio / "manifesto.json").read_text())

    avistamentos = []
    for ponto in manifesto["pontos"]:
        caminho = diretorio / ponto["arquivo"]
        if caminho.exists():
            avistamentos += dissecar(caminho, ponto["label"])

    if not avistamentos:
        raise SystemExit("nenhum avistamento no Traço")

    logicos = correlacionar(avistamentos)
    episodios = segmentar(logicos)

    texto = relatorio(episodios, logicos, avistamentos, manifesto)
    print(texto)
    (diretorio / "relatorio.txt").write_text(texto)
    (diretorio / "analise.json").write_text(
        json.dumps(para_json(episodios, logicos, avistamentos, manifesto),
                   indent=2, ensure_ascii=False))
    print(f"\nSalvo em {diretorio}/relatorio.txt e {diretorio}/analise.json")


if __name__ == "__main__":
    main()
