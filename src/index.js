import { execSync } from "child_process";

// Automatically generate Prisma Client if missing
try {
  execSync("npx prisma generate", { stdio: "inherit" });
} catch (e) {
  console.error("Prisma generation warning:", e);
}

// Import tsx register hook to execute TypeScript at runtime
import "tsx";
import "./index.ts";
