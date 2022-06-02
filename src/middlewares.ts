import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { JwtErrors } from "./errors";

import { setTokensToCookies, tryRefreshToken } from "./utils";

const JWT_SECRET = "very-hard-to-guess";

export const globalErrorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  res.status(500).send({ error });
};

export async function requireAuth(req: any, res: Response, next: NextFunction) {
  const { accessToken, refreshToken } = req.cookies || {};

  if (!accessToken)
    return res.status(400).send({ error: `accessToken not found in cookie` });

  let decoded: any;

  try {
    decoded = jwt.verify(accessToken, JWT_SECRET);
  } catch (err: any) {
    // Refresh token if it's expired
    if (err.name === JwtErrors.Expired && refreshToken) {
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

  next();
}
