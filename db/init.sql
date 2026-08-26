CREATE TABLE produto (
    id   SERIAL PRIMARY KEY,
    nome TEXT NOT NULL
);

INSERT INTO produto (nome) VALUES ('martelo'), ('lanca'), ('tocha');
