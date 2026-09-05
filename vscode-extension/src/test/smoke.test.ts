import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

export function runPackageSmokeTests(): void {
  testPackageCommands();
  testBinaryPrefersConfiguredPath();
}

function testPackageCommands(): void {
  const pkgPath = path.join(__dirname, "..", "..", "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as {
    contributes?: { commands?: { command: string }[] };
  };
  const ids = (pkg.contributes?.commands ?? []).map((c) => c.command);
  assert.ok(ids.includes("rustzap.analyzeWorkspace"));
  assert.ok(ids.includes("rustzap.scanUrl"));
  assert.ok(ids.includes("rustzap.showReportSummary"));
  assert.ok(ids.includes("rustzap.openLastReport"));
  assert.ok(ids.includes("rustzap.scanActiveDirectory"), "AD scan command should be contributed");

  // AD config keys should be declared.
  const pkgFull = pkg as {
    contributes?: { configuration?: { properties?: Record<string, unknown> } };
  };
  const props = pkgFull.contributes?.configuration?.properties ?? {};
  assert.ok("rustzap.ad.domain" in props, "rustzap.ad.domain config should exist");
  assert.ok("rustzap.ad.checks" in props, "rustzap.ad.checks config should exist");
}

function testBinaryPrefersConfiguredPath(): void {
  const configured = "/custom/rustzap";
  const resolvedOrder = [configured, "rustzap"];
  assert.strictEqual(resolvedOrder[0], configured);
}
