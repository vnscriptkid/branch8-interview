import { Response } from "express";
import jwt from "jsonwebtoken";
import bcryptjs from "bcryptjs";

import { pool } from "./db";
import { JWT_ALGO } from "./constants";

export function createTokens(sessionToken: string, userId: string) {
  return {
    accessToken: createAccessToken(sessionToken, userId),
    refreshToken: createRefreshToken(sessionToken),
  };
}

function daysFromNow(days: number): Date {
  return new Date(new Date().setDate(new Date().getDate() + days));
}

export function setTokensToCookies(
  res: Response,
  accessToken: string,
  refreshToken: string
) {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    domain: "localhost",
    path: "/",
    secure: process.env.NODE_ENV === "production",
    expires: daysFromNow(30),
  });

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    domain: "localhost",
    path: "/",
    secure: process.env.NODE_ENV === "production",
  });
}

/*
 * Create new accessToken using current refreshToken
 * Return null if can't make new accessToken
 */
export async function tryRefreshToken(
  refreshToken: string
): Promise<string | null> {
  let decoded: any = null;

  try {
    decoded = jwt.verify(refreshToken, process.env.JWT_SECRET!);
  } catch (err) {
    console.error(`!! failed to verify refreshToken`, err);
    return null;
  }

  const {
    rows: [session],
    rowCount,
  } = await pool.query({
    text: `select * from sessions where session_token = $1 and valid = true;`,
    values: [decoded?.sessionId],
  });

  if (rowCount === 0) {
    console.error(
      `!! valid session not found for this refreshToken ${refreshToken}`
    );
    return null;
  }

  return createAccessToken(session.session_token, session.user_id);
}

function createAccessToken(sessionToken: string, userId: string) {
  return jwt.sign(
    {
      sessionId: sessionToken,
      userId: userId,
    },
    process.env.JWT_SECRET!,
    { algorithm: JWT_ALGO, expiresIn: "1h" }
  );
}

function createRefreshToken(sessionToken: string) {
  return jwt.sign(
    {
      sessionId: sessionToken,
    },
    process.env.JWT_SECRET!,
    { algorithm: JWT_ALGO, expiresIn: "30d" }
  );
}

export async function hashPassword(plainPassword: string) {
  const salt = await bcryptjs.genSalt(10);

  const hashedPassword = await bcryptjs.hash(plainPassword, salt);

  return hashedPassword;
}
