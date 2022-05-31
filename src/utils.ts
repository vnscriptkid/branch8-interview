import { NextFunction, Response } from "express";
import jwt from "jsonwebtoken";
import { pool } from "./db";

const JWT_SECRET = "very-hard-to-guess";

export function createTokens(sessionToken: any, userId: string) {
  const refreshToken = jwt.sign(
    {
      sessionId: sessionToken,
    },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: "30d" }
  );

  const accessToken = jwt.sign(
    {
      sessionId: sessionToken,
      userId: userId,
    },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: "1h" }
  );

  return { accessToken, refreshToken };
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
    expires: new Date(new Date().setDate(new Date().getDate() + 30)),
  });

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    domain: "localhost",
    path: "/",
    secure: process.env.NODE_ENV === "production",
  });
}

export async function requireAuth(req: any, res: Response, next: NextFunction) {
  const { accessToken, refreshToken } = req.cookies || {};

  if (!accessToken)
    return res.status(400).send({ error: `accessToken not found in cookie` });

  let decoded: any;

  try {
    decoded = jwt.verify(accessToken, JWT_SECRET);
  } catch (err) {
    // Refresh token if it's expired
    if ((err as any).name === "TokenExpiredError" && refreshToken) {
      const newAccessToken = await tryRefreshToken(refreshToken);

      if (!newAccessToken)
        return res.send(400).send({ error: `refreshToken is invalid` });

      setTokensToCookies(res, newAccessToken, refreshToken);
    }
    // If not expired, consider as invalid
    else {
      return res.status(400).send({ error: `accessToken is invalid` });
    }
  }
}

async function tryRefreshToken(refreshToken: string): Promise<string | null> {
  let decoded: any = null;

  try {
    decoded = jwt.verify(refreshToken, JWT_SECRET);
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

  const accessToken = jwt.sign(
    {
      sessionId: session.session_token,
      userId: session.user_id,
    },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: "1h" }
  );

  return accessToken;
}
