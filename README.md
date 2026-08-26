# VIRT-IC

Ambiente para **ver e entender** como containers conversam pela rede.

Um mesmo pacote atravessa vários lugares antes de chegar ao destino, e em cada
lugar ele aparece diferente. Ferramentas convencionais mostram um lugar de cada
vez. Este projeto captura em vários pontos ao mesmo tempo, reconhece que os
avistamentos pertencem ao mesmo pacote, e conta a história resultante em fases.

O vocabulário do projeto está em [CONTEXT.md](./CONTEXT.md).

## Cenário do POC

```
curl (host) --> :8080 --> [ web ] --> :5432 --> [ db ]
```

`web` abre uma conexão nova ao banco a cada requisição, de propósito, para que a
conversa completa apareça no Traço.

## Pontos de Observação

| Rótulo        | Onde                     | O que revela                                |
|---------------|--------------------------|---------------------------------------------|
| `host-lo`     | host, loopback           | o pacote como o cliente o enviou            |
| `host-bridge` | host, bridge da rede     | o pacote já traduzido, entre os containers  |
| `web-eth0`    | namespace do web         | o que a aplicação web realmente enxerga     |
| `web-lo`      | namespace do web, loopback | a resolução de nomes, que nunca sai dali  |
| `db-eth0`     | namespace do db          | o que o banco realmente enxerga             |

Nenhum container é modificado: a captura roda no host e entra nos network
namespaces com `nsenter`.

## Requisitos

- Docker e Docker Compose
- `tcpdump`, `nsenter`, `curl` (presentes na maioria das distribuições)
- `tshark` — `sudo apt install tshark`
- acesso `sudo` (a captura precisa entrar nos namespaces)

## Uso

```sh
./run.sh                      # sobe, captura uma requisição, analisa
./run.sh --repeticoes 3       # três requisições no mesmo Traço
```

Saídas em `traces/ultimo/`:

- `*.pcap` — um por Ponto de Observação, abre no Wireshark
- `manifesto.json` — quais pontos foram observados
- `relatorio.txt` — a narrativa por Episódio
- `analise.json` — o modelo semântico, para uma visualização futura consumir

## Como funciona a correlação

Entre Pontos de Observação, o endereço IP e a porta mudam — é justamente o que
o runtime de container faz. Então eles não servem para identificar um pacote.

A tradução, porém, não toca no número de sequência TCP, no identificador do IP,
nem no payload. A chave de correlação é construída sobre esses campos, e por
isso sobrevive à travessia.

Limitações conhecidas do POC: retransmissões produzem chaves idênticas, e
pacotes fragmentados não são remontados.
