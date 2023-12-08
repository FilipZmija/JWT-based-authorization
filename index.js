const express = require("express");
const app = express();
const sqlite = require("sqlite3").verbose();
const cors = require("cors");
const db = require("./models");
const { Users } = require("./models");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { createTokens, validateToken } = require("./JWT");
require("dotenv").config();

app.use(express.json({ limit: "10mb" }));
app.use(cors());
app.use(cookieParser());

//register user
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    const newUser = await Users.create({ username, password: hash });
    res.json({ newUser });
  } catch (e) {
    res.status(400).json(e);
  }
});

//login user
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await Users.findOne({ where: { username: username } });
  if (!user) return res.status(404).json({ message: "User does not exists" });

  const dbPassword = await bcrypt.compare(password, user.password);
  if (!dbPassword) return res.status(400).json({ message: "Invalid password" });

  const accessToken = createTokens(user);

  res.json({ message: "User logged in", accessToken: accessToken });
});

//get user data
app.get("/profile", validateToken, async (req, res) => {
  const id = req.query.id || req.user.id;

  const users = await Users.findAll({ where: { id: id } });
  res.status(200).send({ users });
});

//Get all users
app.get("/users", async (req, res) => {
  const users = await Users.findAll();
  res.status(200).send({ users });
});

//Delete existing user
app.delete("/deleteUser", async (req, res) => {
  const { id } = req.query;
  try {
    const users = await Users.findOne({ where: { id: id } });
    if (!users) return res.status(404).send({ message: "User not found" });

    await Users.destroy({ where: { id: id } });

    res.status(200).send({ message: `User deleted succesfully` });
  } catch (e) {
    res.status(500).send({ message: e.errors.map((item) => item.message) });
  }
});

const PORT = 3001;

(async () => {
  try {
    await db.sequelize.sync();
    app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
  } catch (error) {
    console.error("Error starting server:", error);
  }
})();
