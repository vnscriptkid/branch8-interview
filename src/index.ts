import express from "express";

const app = express();

app.get("/api/status", (req, res) => {
  return res.send({ alive: true });
});

const PORT = 8085;

app.listen(PORT, () => {
  console.log(`server is listening on port ${PORT}`);
});
