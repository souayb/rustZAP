import { runBinaryTests } from "./binary.test";
import { runDiagnosticsTests } from "./diagnostics.test";
import { runReportDisplayTests } from "./reportDisplay.test";
import { runPackageSmokeTests } from "./smoke.test";

function main(): void {
  runDiagnosticsTests();
  runPackageSmokeTests();
  runBinaryTests();
  runReportDisplayTests();
  console.log("All extension unit tests passed.");
}

main();
