import { Pool } from "pg";

export let pool: Pool;

export const connectDb = async () => {
  pool = new Pool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT) || 5432,
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "123456",
    database: process.env.DB_NAME || "auth",
    // number of milliseconds to wait before timing out when connecting a new client
    // by default this is 0 which means no timeout
    connectionTimeoutMillis: 0,
    // number of milliseconds a client must sit idle in the pool and not be checked out
    // before it is disconnected from the backend and discarded
    // default is 10000 (10 seconds) - set to 0 to disable auto-disconnection of idle clients
    idleTimeoutMillis: 0,
    // maximum number of clients the pool should contain
    // by default this is set to 10.
    max: 20,
  });

  await pool.connect();

  console.log(`^^ db connected`);

  await initOnce();
};

async function initOnce() {
  await pool.query(`
    create table if not exists users (
      id serial primary key, 
      email varchar(50) not null unique, 
      password varchar(255) not null
    )
  `);

  await pool.query(`
      create table if not exists sessions (
        id serial primary key,
        session_token varchar(255) not null unique,
        user_id int not null references users(id),
        ip varchar(255) not null,
        user_agent varchar(255) not null,
        updated_at bigint default extract(epoch from current_timestamp),
        created_at bigint default extract(epoch from current_timestamp),
        valid bool not null default false
      )
  `);
}
