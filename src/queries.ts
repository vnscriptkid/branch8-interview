import { pool } from "./db";
import { EmailAlreadyExists, PgErrors } from "./errors";
import { hashPassword } from "./utils";
import crypto from "crypto";

export async function createUser(email: string, plainPassword: string) {
  const hashedPassword = await hashPassword(plainPassword);

  try {
    await pool.query({
      text: `insert into users (email, password) values ($1, $2)`,
      values: [email, hashedPassword],
    });
  } catch (err: any) {
    if (err.code === PgErrors.UniqueViolation) {
      throw new EmailAlreadyExists(`email already exists`);
    }

    throw new Error("failed to create user");
  }
}

export async function findUserByEmail(email: string) {
  const { rowCount, rows } = await pool.query({
    text: `select * from users where email = $1`,
    values: [email],
  });

  return rowCount === 0 ? null : rows[0];
}

export async function createSession({
  userId,
  ip,
  userAgent,
}: {
  userId: string;
  ip: string;
  userAgent: string;
}) {
  const sessionToken = crypto.randomBytes(43).toString("hex");

  const {
    rows: [session],
  } = await pool.query({
    text: `insert into sessions (session_token, user_id, ip, user_agent, valid) values ($1, $2, $3, $4, true) returning *;`,
    values: [sessionToken, userId, ip, userAgent],
  });

  return session;
}
