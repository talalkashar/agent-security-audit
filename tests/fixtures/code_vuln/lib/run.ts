import { exec } from "child_process";

export function thumbnail(file: string) {
  exec(`convert ${file} thumb.png`);
}
