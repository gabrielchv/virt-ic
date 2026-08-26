# PLANO — VIRT-IC

Ambiente virtual para observar e ensinar a rede de containers.

Vocabulário do domínio em [CONTEXT.md](./CONTEXT.md). Este documento é o plano;
não repete definições.

---

## 1. Decisões já tomadas

| # | Decisão | Escolha | Consequência |
|---|---------|---------|--------------|
| 1 | Eixo do trabalho | Didático | Sucesso = pessoa entender, não = detectar falha |
| 2 | Onde está a "container-ness" | Duas camadas correlacionadas | Precisa capturar em vários pontos, não em um |
| 3 | Modo de operação | Post-mortem | Correlação vira problema offline; Traço é reproduzível |
| 4 | Cenário mínimo | Interno + borda | `curl` no host → `web` → `db`; há tradução no ingresso |
| 5 | Mecanismo de captura | `nsenter` a partir do host | Containers intocados; imagem trocável; saída em `pcap` |
| 6 | Modelo de explicação | Episódios (modelo) + raias (apresentação) | Semântica separada da interface |
| 7 | Identidade do pacote | Heurística + `conntrack` como gabarito | Permite **medir** a acurácia da correlação |
| 8 | Contribuição científica | Correlação multiponto | Métrica objetiva, sem depender de recrutar pessoas |
| 9 | Pilha de dissecação | `tshark` + Python 3.12 | Dissecadores prontos; esforço vai para a correlação |

**Pergunta de pesquisa.** É possível reconstruir automaticamente o percurso de um
pacote através das traduções feitas por um runtime de container, a partir de
captura passiva multiponto, e com que acurácia?

**Adiado, decidir no fim:** avaliação didática com usuários (6–10 alunos,
qualitativa). Só se sobrar tempo. Não é o eixo.

---

## 2. Estado atual

Já escrito, **não executado ainda**:

| Arquivo | Papel | Estado |
|---|---|---|
| `compose.yml` | Cenário: `web` + `db` numa bridge, porta 8080 publicada | escrito |
| `web/app.py`, `web/Dockerfile` | Servidor que abre conexão nova ao banco por requisição | escrito |
| `db/init.sql` | Tabela e três linhas | escrito |
| `poc/capture.py` | Coleta o Traço nos 5 Pontos de Observação | escrito, não testado |
| `poc/analyze.py` | Dissecação, correlação, segmentação, relatório | escrito, não testado |
| `run.sh` | Ponta a ponta | escrito, não testado |
| `CONTEXT.md` | Glossário | escrito |

Pendências de ambiente:

- `tshark` **ausente** no host → `sudo apt install tshark`
- imagens Docker não baixadas (download foi interrompido)

Nada foi validado em execução. Todo número abaixo é estimativa, não medição.

---

## 3. Etapas

### Etapa 0 — Fazer o POC rodar uma vez

Objetivo: um relatório de Episódios sair na tela, de ponta a ponta.

1. Instalar `tshark`.
2. `docker compose up -d --build --wait` até o cenário subir de fato.
3. Rodar `poc/capture.py` e conferir que os 5 `pcap` têm pacotes. Ponto mais
   provável de falhar: `host-lo` — verificar se o tráfego para a porta publicada
   passa mesmo por `lo` neste host, ou se vai por outra interface.
4. Rodar `poc/analyze.py` e ler o relatório à mão contra o Wireshark.

Critério de pronto: o relatório mostra, na ordem, resolução de nome → abertura
de conexão → requisição → autenticação → consulta → resposta → encerramento.

Riscos concretos desta etapa:

- **A resolução de nome pode não aparecer.** Se o `glibc` do container guardar o
  resultado, a segunda requisição não consulta o resolvedor. Verificar; se
  ocorrer, é conteúdo didático, não defeito.
- **O protocolo do banco pode não ser dissecado.** Confirmar que `sslmode=disable`
  de fato manteve texto claro. Se o `tshark` não reconhecer, forçar com
  `-d tcp.port==5432,pgsql`.
- **HTTP dentro do container está na porta 8000**, fora da lista padrão do
  dissecador. Já tratado com `-d tcp.port==8000,http`; confirmar que funcionou.

### Etapa 1 — Fechar a correlação e medir

Aqui mora a contribuição. Só começa depois da Etapa 0 fechar.

1. Coletar a tabela de `conntrack` durante a captura, como gabarito independente
   da tradução ocorrida.
2. Comparar o resultado da heurística contra o gabarito e produzir: acertos,
   falsos pareamentos, avistamentos órfãos.
3. Tratar os casos que hoje quebram, na ordem:
   - confirmação pura (payload vazio) → herdar a identidade pelo fluxo
   - retransmissão → dois datagramas com a mesma chave; desempatar por tempo e
     por Ponto de Observação
   - fragmentação → decidir se remonta ou se declara fora de escopo
4. Fixar o relatório de acurácia como saída padrão do analisador.

Critério de pronto: um número de acurácia, reprodutível, sobre N execuções.

### Etapa 2 — Cenários adversos

A contribuição fica rasa se a correlação acertar sempre. Introduzir dificuldade
de propósito, e medir a degradação:

- perda e retransmissão induzidas (`tc netem` na interface do container)
- várias conexões simultâneas reusando faixa de portas
- MTU reduzido, para forçar fragmentação
- egress para fora do host, que traz o outro tipo de tradução

Cada cenário vira uma linha na tabela de resultados da monografia.

### Etapa 3 — Apresentação em raias

Só depois que o modelo semântico estiver estável. O analisador já emite
`analise.json` justamente para que esta etapa não obrigue a mexer na análise.

- uma raia por Ponto de Observação
- uma seta por Avistamento, ligando as raias do mesmo Pacote Lógico
- destaque onde houve tradução — é a lição central
- Episódios como faixas agrupando as setas

Formato: página estática lendo o JSON. Sem servidor, sem framework pesado.

### Etapa 4 — Escrita

Estrutura provável: contexto de rede em containers, trabalhos relacionados,
método de captura multiponto, algoritmo de correlação, avaliação de acurácia,
cenários adversos, ferramenta didática, limitações, trabalhos futuros.

Trabalhos futuros óbvios (e são gancho de mestrado): captura por eBPF, que este
host já suporta (BTF presente), e operação ao vivo em vez de post-mortem.

---

## 4. Riscos do projeto

| Risco | Impacto | O que fazer |
|---|---|---|
| Correlação acerta sempre no cenário fácil | Contribuição parece trivial | Etapa 2 existe por isso |
| Trabalho relacionado já resolveu isso | Refazer o feito | Revisão bibliográfica **antes** da Etapa 1 |
| Escopo escorregar para ferramenta de teste | Perde o eixo didático | Decisão 1 é o critério de corte |
| `tshark` lento em Traço grande | Atrasa iteração | Só otimizar se doer; alternativa já mapeada |
| Avaliação com usuários virar o projeto | Não termina | Está adiada e é opcional |

---

## 5. Próximo passo

Etapa 0, item 1: instalar `tshark`. Depois subir o cenário e coletar o primeiro
Traço de verdade.
