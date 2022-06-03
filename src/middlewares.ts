import { NextFunction, Request, Response } from "express";

import { setTokensToCookies, tryRefreshToken, verifyJwt } from "./utils";

export const globalErrorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  res.status(500).send({ error });
};

export async function requireAuth(req: any, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(403).send({ error: `You are not authorized` });
  }

  next();
}

export async function deserializeUser(
  req: any,
  res: Response,
  next: NextFunction
) {
  const { accessToken, refreshToken } = req.cookies || {};

  if (!accessToken) return next();

  const { decoded, expired } = verifyJwt(accessToken);

  if (decoded) {
    console.log(`@@ token valid`);
    attachUserToReq(req, decoded);

    return next();
  }

  if (expired && refreshToken) {
    const newAccessToken = await tryRefreshToken(refreshToken);

    if (newAccessToken) {
      const { decoded } = verifyJwt(accessToken);

      attachUserToReq(req, decoded);

      setTokensToCookies(res, newAccessToken, refreshToken);
      console.log(`^^ token got revoked`);
    }
  }

  next();
}

function attachUserToReq(req: any, decoded: any) {
  req.user = {
    userId: decoded?.userId,
  };
}
