require("dotenv").config();

import { startServer } from "./startServer";
import { connectDb } from "./db";

async function main() {
  connectDb()
    .then(() => {
      startServer();
    })
    .catch((err) => {
      console.log(`!! db connection err: `, err);
    });
}

main();
