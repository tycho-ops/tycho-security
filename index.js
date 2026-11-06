/**
 * Entry point of the @tycho/security module: runs the bundled shell script.
 * @license AGPL-3.0-only
 */
import { fileURLToPath } from "url";

const script = fileURLToPath(new URL("./bin/security.sh", import.meta.url));

/**
 * Runs the module.
 * @param {string[]} args Arguments after `tycho <command>`.
 * @param {{ env: Record<string, string> }} ctx Context given by the core.
 * @returns {Promise<number>} Exit code.
 */
export async function run(args, ctx) {
   const child = Bun.spawn(["bash", script, ...args], { env: ctx.env, stdio: ["inherit", "inherit", "inherit"] });
   return await child.exited;
}
