import { execFile } from "child_process";

export function thumbnail(file: string) {
  execFile("convert", ["--", file, "thumb.png"]);
}
