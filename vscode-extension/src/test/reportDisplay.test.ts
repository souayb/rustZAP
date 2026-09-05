import * as assert from "assert";
import { findingLocationLabel } from "../report";
import { attackPlanTargetUrl } from "../session";

export function runReportDisplayTests(): void {
  testFindingLocationLabel();
  testAttackPlanRelativeUrl();
}

function testFindingLocationLabel(): void {
  const label = findingLocationLabel({
    id: "1",
    title: "x",
    severity: "high",
    url: "file:///x",
    description: "d",
    solution: "s",
    plugin: "p",
    location: { file: "static/app.js", line_start: 2 },
  });
  assert.strictEqual(label, "static/app.js:2");
}

function testAttackPlanRelativeUrl(): void {
  assert.strictEqual(
    attackPlanTargetUrl({ url: "/login", method: "POST", params: [], reason: "form" }, "https://lab.example.com"),
    "https://lab.example.com/login"
  );
  assert.strictEqual(
    attackPlanTargetUrl({ url: "/login", method: "POST", params: [], reason: "form" }, "/tmp/app"),
    undefined
  );
}
