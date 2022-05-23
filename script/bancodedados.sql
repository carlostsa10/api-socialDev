CREATE DATABASE socialdev;

CREATE TABLE IF NOT EXISTS usuarios(
	id serial PRIMARY KEY, 
  nome text NOT NULL, 
  sobrenome text NOT NULL,
 	email text NOT NULL UNIQUE, 
  username text NOT NULL,
 	senha text NOT NULL
);

CREATE TABLE IF NOT EXISTS publicacoes(
	id serial PRIMARY KEY,
  descricao text,
  curtidas int,
  comentarios int 
  compartilhamentos int,

);
