import { Response } from "express";
import jwt from "jsonwebtoken";
import bcryptjs from "bcryptjs";

import { JWT_ALGO } from "./constants";
import { JwtErrors } from "./errors";
import { findValidSession } from "./queries";

export function createTokens(sessionToken: string, userId: string) {
  return {
    accessToken: createAccessToken(sessionToken, userId),
    refreshToken: createRefreshToken(sessionToken),
  };
}

export function setTokensToCookies(
  res: Response,
  accessToken: string,
  refreshToken?: string
) {
  if (refreshToken) {
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      domain: "localhost",
      path: "/",
      secure: process.env.NODE_ENV === "production",
      // maxAge: 3600 * 1000, // 1 hour
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      domain: "localhost",
      path: "/",
      secure: process.env.NODE_ENV === "production",
      maxAge: 30 * 24 * 3600 * 1000, // 30 days
    });
  }
}

/*
 * Create new accessToken using current refreshToken
 * Return null if can't make new accessToken
 */
export async function tryRefreshToken(
  refreshToken: string
): Promise<string | null> {
  const { decoded } = verifyJwt(refreshToken);

  if (!decoded) return null;

  const session = await findValidSession(decoded?.sessionId);

  if (!session) return null;

  return createAccessToken(session.session_token, session.user_id);
}

function createAccessToken(sessionToken: string, userId: string) {
  return jwt.sign(
    {
      sessionId: sessionToken,
      userId: userId,
    },
    process.env.JWT_SECRET!,
    { algorithm: JWT_ALGO, expiresIn: "10s" }
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

export function verifyJwt(token: string): {
  decoded: null | any;
  expired: boolean;
} {
  try {
    let decoded: any = jwt.verify(token, process.env.JWT_SECRET!);
    return {
      decoded,
      expired: false,
    };
  } catch (err: any) {
    if (err.name === JwtErrors.Expired) {
      return {
        decoded: null,
        expired: true,
      };
    }

    return {
      decoded: null,
      expired: false,
    };
  }
}
