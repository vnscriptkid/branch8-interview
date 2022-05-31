import cookieParser from "cookie-parser";
import express, { NextFunction, query, Request, Response } from "express";
import bcryptjs, { compare } from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";

import "express-async-errors";

import { connectDb, pool } from "./db";
import { createTokens, requireAuth, setTokensToCookies } from "./utils";

const app = express();

app.use(express.json());
app.use(cookieParser());

enum PgErrors {
  UniqueViolation = "23505",
}

app.get("/api/guard", requireAuth, async (req, res) => {
  return res.status(200).send({ data: "only auth user can see" });
});

app.get("/api/status", (req, res) => {
  return res.send({ alive: true });
});

app.get("/api/auth/logout", (req, res) => {
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");

  return res.send({ done: true });
});

app.get("/api/guest", (req, res) => {
  return res.send({ guestSite: true });
});

app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password)
    return res.status(400).send({ error: `email or password are missing` });

  const salt = await bcryptjs.genSalt(10);

  const hashedPassword = await bcryptjs.hash(password, salt);

  try {
    await pool.query({
      text: `insert into users (email, password) values ($1, $2)`,
      values: [email, hashedPassword],
    });
  } catch (err: any) {
    if (err.code === PgErrors.UniqueViolation) {
      return res.status(400).send({ error: `email already exists` });
    }

    throw err;
  }

  return res.status(201).send({ message: "success" });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password)
    return res.status(400).send({ error: `email or password are missing` });

  const { rowCount, rows } = await pool.query({
    text: `select * from users where email = $1`,
    values: [email],
  });

  if (rowCount === 0) return res.status(400).send({ error: `email not found` });

  const hashedPassword = rows[0].password;

  const isPasswordCorrect = await compare(password, hashedPassword);

  if (!isPasswordCorrect)
    return res.status(400).send({ error: `password is wrong` });

  // create session
  const [sessionToken, userId, ip, userAgent] = [
    crypto.randomBytes(43).toString("hex"),
    rows[0].id,
    req.ip,
    req.headers["user-agent"],
  ];
  const {
    rows: [session],
  } = await pool.query({
    text: `insert into sessions (session_token, user_id, ip, user_agent, valid) values ($1, $2, $3, $4, true) returning *;`,
    values: [sessionToken, userId, ip, userAgent],
  });

  const { accessToken, refreshToken } = createTokens(
    session.session_token,
    userId
  );

  setTokensToCookies(res, accessToken, refreshToken);

  return res.status(200).send({
    user: {
      id: rows[0].id,
      email: rows[0].email,
    },
    refreshToken,
    accessToken,
  });
});

app.get("/api/auth/me", async (req, res) => {
  return res.send({ done: true });
});

app.use((error: any, req: Request, res: Response, next: NextFunction) => {
  res.status(500).send({ error });
});

const PORT = 8085;

app.listen(PORT, async () => {
  await connectDb();
  console.log(`server is listening on port ${PORT}`);
});
