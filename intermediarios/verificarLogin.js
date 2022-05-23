const conexao = require("../conexao");
const jwtSecret = process.env.JWT_SECRET;
const jwt = require("jsonwebtoken");

const verificarLogin = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({
      mensagem: "Não foi possível autenticar o usuário.",
    });
  }

  try {
    const tokenAutorizado = token.replace("Bearer ", "").trim();
    const { id } = await jwt.verify(tokenAutorizado, jwtSecret);
    const queryUsuarioLogado = "select * from usuarios where id = $1";

    const { rows, rowCount } = await conexao.query(queryUsuarioLogado, [id]);
    if (rowCount === 0) {
      return res.status(401).json({
        mensagem: "O usuário não foi encontrado.",
      });
    }
    const usuario = await conexao.query(
      "select id, nome, email from usuarios where id = $1",
      [id]
    );
    req.usuarioLogado = rows[0];
    next();
  } catch (error) {
    return res.status(401).json({
      mensagem: "Não foi possível autenticar o usuário.",
    });
  }
};

module.exports = {
  verificarLogin,
};
