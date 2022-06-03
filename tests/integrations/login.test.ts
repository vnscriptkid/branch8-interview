import { connectDb, initOnce, pool } from "../../src/db";
import { startServer } from "../../src/startServer";
import { cleanUpDb } from "../utils/db";
import request from "supertest";
import { processCookie } from "../utils/helpers";
import jwt from "jsonwebtoken";

let server: any = null;

beforeEach(async () => {
  await cleanUpDb();
  await initOnce();
});

beforeAll(async () => {
  await connectDb();
  server = await startServer();
});

// afterAll(async () => {
//   await pool.end();
//   if (server) await server.close();
// });
afterAll(() => {
  server.close();
});

describe("login failure", () => {
  test("invalid email", async () => {
    /* ACTION */
    const res = await request(server).post("/api/auth/login").send({
      email: "example@gmail.com",
      password: "123456",
    });

    /* ASSERT */
    expect(res.statusCode).toEqual(400);
    expect(res.body).toEqual({ error: "email is invalid" });
  });

  test("invalid password", async () => {
    /* ARRANGE */
    await request(server).post("/api/auth/register").send({
      email: "example@gmail.com",
      password: "123456",
    });

    /* ACTION */
    const res = await request(server).post("/api/auth/login").send({
      email: "example@gmail.com",
      password: "WRONG-PASSWORD",
    });

    /* ASSERT */
    expect(res.statusCode).toEqual(400);
    expect(res.body).toEqual({ error: "password is wrong" });
  });
});

describe("login success", () => {
  test("happy case", async () => {
    /* ARRANGE */
    await request(server).post("/api/auth/register").send({
      email: "example@gmail.com",
      password: "123456",
    });

    /* ACTION */
    const res = await request(server).post("/api/auth/login").send({
      email: "example@gmail.com",
      password: "123456",
    });

    /* ASSERT */
    expect(res.statusCode).toEqual(200);
    expect(res.body).toEqual({
      user: {
        email: "example@gmail.com",
        id: 1,
      },
    });
    const [cookie1, cookie2] = res.headers["set-cookie"];
    expect(processCookie(cookie1)).toMatchObject({
      accessToken: expect.any(String),
      Domain: "localhost",
      Path: "/",
      HttpOnly: true,
    });
    expect(processCookie(cookie2)).toMatchObject({
      refreshToken: expect.any(String),
      Domain: "localhost",
      Path: "/",
      HttpOnly: true,
    });
  });
});
