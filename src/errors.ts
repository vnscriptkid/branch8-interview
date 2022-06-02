export enum PgErrors {
  UniqueViolation = "23505",
}

export class EmailAlreadyExists extends Error {}

export enum JwtErrors {
  Expired = "TokenExpiredError",
}
