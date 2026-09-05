import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export function rustzapExeName(): string {
  return process.platform === "win32" ? "rustzap.exe" : "rustzap";
}

export function exists(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export function isExecutable(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function cargoBuildCandidates(repoRoot: string): string[] {
  const exe = rustzapExeName();
  return [
    path.join(repoRoot, "target", "release", exe),
    path.join(repoRoot, "target", "debug", exe),
  ];
}

export function isRustzapRepo(dir: string): boolean {
  const cargo = path.join(dir, "Cargo.toml");
  if (!exists(cargo)) {
    return false;
  }
  try {
    const text = fs.readFileSync(cargo, "utf8");
    return /^name\s*=\s*"rustzap"/m.test(text);
  } catch {
    return false;
  }
}

/** Walk parents from startDir for a rustzap Cargo tree with a built binary. */
export function findBuiltBinaryFrom(startDir: string | undefined): string | undefined {
  if (!startDir) {
    return undefined;
  }

  let dir = path.resolve(startDir);
  for (let depth = 0; depth < 24; depth++) {
    if (isRustzapRepo(dir)) {
      for (const candidate of cargoBuildCandidates(dir)) {
        if (exists(candidate) && (process.platform === "win32" || isExecutable(candidate))) {
          return candidate;
        }
      }
    }

    const parent = path.dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }

  return undefined;
}

export function pathEntries(): string[] {
  const sep = process.platform === "win32" ? ";" : ":";
  const entries = (process.env.PATH ?? "").split(sep).filter(Boolean);

  const home = process.env.HOME ?? process.env.USERPROFILE ?? os.homedir();
  if (home) {
    entries.push(path.join(home, ".cargo", "bin"));
  }

  if (process.platform === "win32") {
    entries.push("C:\\Program Files\\RustZAP");
  } else {
    entries.push("/usr/local/bin", "/opt/homebrew/bin");
  }

  return [...new Set(entries.map((e) => path.resolve(e)))];
}

/** Locate rustzap on PATH (including ~/.cargo/bin). */
export function findOnPath(): string | undefined {
  const exe = rustzapExeName();
  for (const dir of pathEntries()) {
    const candidate = path.join(dir, exe);
    if (exists(candidate) && (process.platform === "win32" || isExecutable(candidate))) {
      return candidate;
    }
  }
  return undefined;
}

export interface ResolveOptions {
  configuredPath?: string;
  searchRoots?: string[];
}

/** Resolve rustzap: setting → walk-up cargo build → PATH. */
export function resolveRustzapPath(options: ResolveOptions = {}): string | undefined {
  const configured = (options.configuredPath ?? "").trim();
  if (configured) {
    return exists(configured) ? configured : undefined;
  }

  for (const root of options.searchRoots ?? []) {
    const built = findBuiltBinaryFrom(root);
    if (built) {
      return built;
    }
  }

  return findOnPath();
}

export function ensureRustzapPath(options: ResolveOptions = {}): string {
  const configured = (options.configuredPath ?? "").trim();
  const resolved = resolveRustzapPath(options);

  if (configured && !resolved) {
    throw new Error(`rustzap.path is set but not found: ${configured}`);
  }

  if (!resolved) {
    const hint = options.searchRoots?.[0]
      ? ` Build with \`cargo build --release\` in the RustZAP repo, or set rustzap.path in settings.`
      : " Install RustZAP or set rustzap.path in settings.";
    throw new Error(`rustzap executable not found.${hint}`);
  }

  return resolved;
}
