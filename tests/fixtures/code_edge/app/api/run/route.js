import childProcess from "child_process";
import { promisify } from "util";
import { execFile } from "node:child_process";

const execAsync = promisify(childProcess.exec);

export async function POST(req) {
  const { repo, dir } = await req.json();
  await execAsync(`git clone ${repo}`);
  childProcess.exec(`ls ${dir}`);
  execFile("git", ["status"]);
  return Response.json({ ok: true });
}
