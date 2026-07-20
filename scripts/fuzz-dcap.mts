import { $ } from "bun";

const ALL_TARGETS = [
  "quote_parse",
  "collateral_parse",
  "verify_quote",
  "verify_collateral",
];

const FUZZ_DIR = "dcap-verify";
const secs = Number(process.env.FUZZ_SECS ?? 60);
const envTargets =
  process.env.FUZZ_TARGETS?.trim().split(/\s+/).filter(Boolean) ?? [];
const targets = envTargets.length ? envTargets : ALL_TARGETS;

const unknown = targets.filter((t) => !ALL_TARGETS.includes(t));
if (unknown.length || !Number.isFinite(secs) || secs <= 0) {
  const problem = unknown.length
    ? `unknown fuzz target(s): ${unknown.join(", ")} (known: ${ALL_TARGETS.join(", ")})`
    : `FUZZ_SECS must be a positive number, got '${process.env.FUZZ_SECS}'`;
  console.error(`\x1b[31m${problem}\x1b[0m`);
  process.exit(2);
}

// cargo-fuzz defaults to the triple *it* was compiled for, so a prebuilt
// musl-static cargo-fuzz (e.g. from taiki-e/install-action in CI) silently
// targets x86_64-unknown-linux-musl, where ASan rejects static libc. Pin the
// build to the actual host triple instead.
const host = (await $`rustc +nightly -vV`.text()).match(/^host: (.+)$/m)?.[1];
if (!host) {
  console.error("\x1b[31mcould not determine host triple from `rustc +nightly -vV`\x1b[0m");
  process.exit(2);
}

let failures = 0;

for (const target of targets) {
  const startLine = `\x1b[36m▶ ${target}: fuzzing for ${secs}s…\x1b[0m`;
  if (process.stdout.isTTY) {
    process.stdout.write(startLine);
  } else {
    console.log(startLine);
  }

  const result = await $`cargo +nightly fuzz run ${target} --target ${host} -- -max_total_time=${secs}`
    .cwd(FUZZ_DIR)
    .quiet()
    .nothrow();
  const log = result.stdout.toString() + result.stderr.toString();
  if (process.stdout.isTTY) {
    process.stdout.write("\r\x1b[2K");
  }

  const stats = log.match(/#(\d+)\s+DONE\s+cov: (\d+) ft: \d+ corp: (\d+)/);
  const done = log.match(/^Done (\d+) runs in (\d+) second/m);

  if (result.exitCode === 0) {
    const runs = Number(done?.[1] ?? stats?.[1] ?? 0).toLocaleString("en-US");
    const detail = stats ? `, cov ${stats[2]}, corpus ${stats[3]}` : "";
    console.log(
      `\x1b[32m✅ ${target}: ${runs} runs in ${done?.[2] ?? secs}s${detail} — no crashes\x1b[0m`
    );
  } else {
    failures += 1;
    const logPath = `${FUZZ_DIR}/fuzz/target/${target}.failure.log`;
    await Bun.write(logPath, log);
    const why =
      log.match(/SUMMARY: libFuzzer: (.+)/)?.[1]?.trim() ??
      log.match(/^thread .* panicked at .*$/m)?.[0] ??
      `exit code ${result.exitCode}`;
    const artifact = log.match(/Test unit written to (\S+)/)?.[1];
    console.log(`\x1b[31m❌ ${target}: ${why}\x1b[0m`);
    if (artifact) {
      console.log(`   crashing input: ${artifact}`);
    }
    console.log(`   full log: ${logPath}`);
  }
}

if (failures) {
  console.log(
    `\x1b[31m💥 ${failures}/${targets.length} fuzz target(s) failed\x1b[0m`
  );
  process.exit(1);
}
console.log(
  `\x1b[32m🎉 ${targets.length}/${targets.length} fuzz targets clean (${secs}s each)\x1b[0m`
);
