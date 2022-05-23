const express = require("express");
const usuarios = require("./controladores/usuarios");
const { verificarLogin } = require("./intermediarios/verificarLogin");

const rotas = express();

rotas.post("/usuario", usuarios.cadastrarUsuario);
rotas.post("/login", usuarios.login);
rotas.use(verificarLogin);
rotas.get("/usuario", usuarios.detalharUsuario);
rotas.put("/usuario", usuarios.atualizarUsuario);

module.exports = rotas;