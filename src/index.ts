import express from "express";
import { connectDb } from "./db";

const app = express();

app.get("/api/status", (req, res) => {
  return res.send({ alive: true });
});

app.post("/api/auth/register", async (req, res) => {
  return res.send({ done: true });
});

app.post("/api/auth/login", async (req, res) => {
  return res.send({ done: true });
});

app.get("/api/auth/me", async (req, res) => {
  return res.send({ done: true });
});

const PORT = 8085;

app.listen(PORT, async () => {
  await connectDb();
  console.log(`server is listening on port ${PORT}`);
});
