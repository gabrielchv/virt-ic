"""Servidor web mínimo do cenário.

Abre uma conexão NOVA ao banco a cada requisição, de propósito: assim cada
execução do cenário produz a conversa completa (resolução de nome, abertura de
conexão, autenticação, consulta, resposta, encerramento) no Traço capturado.
Um pool de conexões esconderia justamente o que queremos ensinar.
"""

import http.server
import json
import socketserver

import psycopg

# sslmode=disable mantém o protocolo do PostgreSQL em texto claro, para que o
# dissecador consiga identificar as mensagens. Com TLS o Traço vira bytes opacos.
DSN = (
    "host=db port=5432 dbname=app user=app password=secret "
    "connect_timeout=5 sslmode=disable"
)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with psycopg.connect(DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, nome FROM produto ORDER BY id")
                rows = cur.fetchall()

        body = json.dumps({"produtos": rows}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", 8000), Handler) as srv:
        srv.serve_forever()
