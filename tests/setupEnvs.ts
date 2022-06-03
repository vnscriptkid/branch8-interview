console.log(`@@ setup env`);

(process.env as any).PORT = 8088;
(process.env as any).DB_NAME = "auth_test";
(process.env as any).JWT_SECRET = "hardtoguess";
