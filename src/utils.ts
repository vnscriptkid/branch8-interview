import { Response } from "express";
import jwt from "jsonwebtoken";

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
