const { sign, verify } = require("jsonwebtoken");

const createTokens = (user) => {
  const accessToken = sign(
    { username: user.username, id: user.id },
    process.env.SECRET_TOKEN
  );
  return accessToken;
};

const validateToken = (req, res, next) => {
  const accessToken = req.headers.authorization.split(" ")[1];
  if (!accessToken)
    return res.status(401).json({ message: "No token provided" });

  try {
    const validToken = verify(accessToken, process.env.SECRET_TOKEN);
    if (validToken) {
      req.authenticated = true;
      req.user = { id: validToken.id, username: validToken.username };
      return next();
    }
  } catch (err) {
    return res.status(401).json(err);
  }
};

module.exports = { createTokens, validateToken };
