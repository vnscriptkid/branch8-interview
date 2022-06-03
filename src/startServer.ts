import cookieParser from "cookie-parser";
import express from "express";
import { compare } from "bcryptjs";
import path from "path";

import "express-async-errors";

import { createTokens, setTokensToCookies } from "./utils";
import { EmailAlreadyExists } from "./errors";
import {
  deserializeUser,
  globalErrorHandler,
  requireAuth,
} from "./middlewares";
import { createSession, createUser, findUserByEmail } from "./queries";

export const startServer = () => {
  const app = express();

  app.use(express.json());
  app.use(cookieParser());
  app.use(deserializeUser);

  app.get("/", function (req, res) {
    res.sendFile(path.join(__dirname, "../public", "index.html"));
  });

  // HEALTH CHECK
  app.get("/api/status", (req, res) => {
    return res.send({ alive: true });
  });

  // PPL AREAS
  app.get("/api/guard", requireAuth, async (req, res) => {
    return res.status(200).send({ data: "only auth user can see" });
  });

  app.get("/api/guest", (req, res) => {
    return res.send({ guestSite: true });
  });

  // AUTH ROUTES
  app.get("/api/auth/logout", (req, res) => {
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    return res.send({ done: true });
  });

  app.post("/api/auth/register", async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password)
      return res.status(400).send({ error: `email or password are missing` });

    try {
      await createUser(email, password);
    } catch (err: any) {
      if (err instanceof EmailAlreadyExists)
        return res.status(400).send({ error: err.message });

      return res.status(500).send({ error: err.message });
    }

    return res.status(201).send({ message: "success" });
  });

  app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password)
      return res.status(400).send({ error: `email or password are missing` });

    const user = await findUserByEmail(email);

    if (!user) return res.status(400).send({ error: `email is invalid` });

    const isPasswordCorrect = await compare(password, user.password);

    if (!isPasswordCorrect)
      return res.status(400).send({ error: `password is wrong` });

    const session = await createSession({
      userId: user.id,
      ip: req.ip,
      userAgent: req.headers["user-agent"]!,
    });

    const { accessToken, refreshToken } = createTokens(
      session.session_token,
      user.id
    );

    setTokensToCookies(res, accessToken, refreshToken);

    return res.status(200).send({
      user: {
        id: user.id,
        email: user.email,
      },
    });
  });

  app.use(globalErrorHandler);

  return new Promise((resolve) => {
    const port = process.env.PORT || 8085;
    const server = app.listen(port, async () => {
      console.log(`server is listening on port ${port}`);
      resolve(server);
    });
  });
};
