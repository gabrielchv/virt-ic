# CONTEXT

Glossário do domínio. Só vocabulário — sem decisões de implementação.

## Cenário

Definição declarativa de uma topologia de containers mais um roteiro de tráfego a ser
exercitado. Um Cenário é reproduzível: executá-lo duas vezes produz Traços comparáveis.

Exemplo: `curl` no host → `web` (porta publicada) → `db`.

## Ponto de Observação

Lugar onde o tráfego é capturado, identificado pelo par (network namespace, interface).
Pontos distintos enxergam o mesmo tráfego de formas distintas — essa diferença é o objeto
de estudo do projeto, não um detalhe.

Exemplos: `host/eth0`, `host/docker0`, `web/eth0`, `web/lo`, `db/eth0`.

## Avistamento

Uma ocorrência capturada de um pacote em **um** Ponto de Observação.

## Pacote Lógico

O datagrama único que deu origem a um ou mais Avistamentos. Um Pacote Lógico atravessando
três Pontos de Observação produz três Avistamentos.

Distinguir os dois é essencial: sem isso, uma visualização multiponto sugere que houve três
pacotes onde houve um — exatamente o erro conceitual que o projeto existe para corrigir.

## Correlação

O ato de agrupar Avistamentos no Pacote Lógico que os originou. Difícil precisamente onde a
tradução de endereços acontece, porque IP e porta mudam entre Pontos de Observação.

## Traço

Todos os Avistamentos coletados durante uma execução de um Cenário, em todos os Pontos de
Observação, sob um relógio comum. Unidade de dado persistida e versionável.

## Episódio

Segmento de um Traço com significado didático próprio — a unidade de explicação.
Um Episódio agrupa os Pacotes Lógicos que participam de uma mesma fase da conversa.

Exemplos: resolução de nome, abertura de conexão, autenticação, consulta, resposta, encerramento.

O Episódio é a unidade que o usuário lê. O Pacote Lógico é a evidência que sustenta o Episódio.

## Tradução

Reescrita de endereço ou porta feita pelo runtime de container entre dois Pontos de
Observação. Invisível para as aplicações dentro dos containers.

Ocorre no ingresso de porta publicada, na saída para fora do host, e no acesso ao resolvedor
de nomes embutido.
