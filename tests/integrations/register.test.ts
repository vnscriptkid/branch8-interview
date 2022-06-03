import axios from "axios";
import { connectDb, initOnce, pool } from "../../src/db";
import { startServer } from "../../src/startServer";
import { cleanUpDb } from "../utils/db";
import request from "supertest";

let server: any = null,
  baseURL: string;

beforeEach(async () => {
  await cleanUpDb();
  await initOnce();
});

beforeAll(async () => {
  await connectDb();
  server = await startServer();
  baseURL = `http://localhost:${process.env.PORT}/api/auth/register`;
});

beforeAll(async () => {
  await server.close();
});

describe("register", () => {
  test("happy case", async () => {
    /* ACTION */
    const res = await request(server).post("/api/auth/register").send({
      email: "example@gmail.com",
      password: "123456",
    });
    /* ASSERT */
    expect(res.body).toEqual({ message: "success" });

    const {
      rowCount,
      rows: [user],
    } = await pool.query(`select * from users;`);

    expect(rowCount).toEqual(1);
    expect(user).toMatchObject({
      email: "example@gmail.com",
      id: 1,
      password: expect.any(String),
    });
  });

  test("missing email", async () => {
    /* ACTION */
    const res = await request(server).post("/api/auth/register").send({
      password: "123456",
    });
    /* ASSERT */
    expect(res.body).toEqual({ error: "email or password are missing" });

    const { rowCount } = await pool.query(`select * from users;`);

    expect(rowCount).toEqual(0);
  });

  test("missing password", async () => {
    /* ACTION */
    const res = await request(server).post("/api/auth/register").send({
      email: "example@gmail.com",
    });
    /* ASSERT */
    expect(res.body).toEqual({ error: "email or password are missing" });

    const { rowCount } = await pool.query(`select * from users;`);

    expect(rowCount).toEqual(0);
  });

  test("duplicate email", async () => {
    /* Arrange */
    await request(server).post("/api/auth/register").send({
      email: "example@gmail.com",
      password: "123456",
    });

    /* ACTION */
    const res = await request(server).post("/api/auth/register").send({
      email: "example@gmail.com",
      password: "123456",
    });

    /* ASSERT */
    expect(res.body).toEqual({ error: "email already exists" });

    const { rowCount } = await pool.query(`select * from users;`);

    expect(rowCount).toEqual(1);
  });
});
