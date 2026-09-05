import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import {
  findBuiltBinaryFrom,
  isRustzapRepo,
  resolveRustzapPath,
} from "../binaryCore";

export function runBinaryTests(): void {
  testIsRustzapRepo();
  testFindBuiltBinaryFromFixtureWalkUp();
  testConfiguredPathWins();
}

function repoRootFromTest(): string {
  return path.join(__dirname, "..", "..", "..");
}

function testIsRustzapRepo(): void {
  const repoRoot = repoRootFromTest();
  assert.strictEqual(isRustzapRepo(repoRoot), true);
  assert.strictEqual(isRustzapRepo(path.join(repoRoot, "tests/fixtures/native_app")), false);
}

function testFindBuiltBinaryFromFixtureWalkUp(): void {
  const repoRoot = repoRootFromTest();
  const fixture = path.join(repoRoot, "tests", "fixtures", "native_app");
  const release = path.join(
    repoRoot,
    "target",
    "release",
    process.platform === "win32" ? "rustzap.exe" : "rustzap"
  );

  if (!fs.existsSync(release)) {
    console.log("skip: no built rustzap binary at", release);
    return;
  }

  const found = findBuiltBinaryFrom(fixture);
  assert.ok(found, "should walk up from fixture to repo target/release/rustzap");
  assert.strictEqual(path.resolve(found!), path.resolve(release));
}

function testConfiguredPathWins(): void {
  const fake = path.join(path.sep, "no-such-rustzap-binary");
  assert.strictEqual(
    resolveRustzapPath({ configuredPath: fake, searchRoots: ["/tmp"] }),
    undefined
  );
}
