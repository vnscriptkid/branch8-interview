import { pool } from "../../src/db";

export async function cleanUpDb() {
  await pool.query(`DROP TABLE IF EXISTS sessions;`);
  await pool.query(`DROP TABLE IF EXISTS users;`);
}
