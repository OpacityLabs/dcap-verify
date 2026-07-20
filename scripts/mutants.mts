import { $ } from "bun";

// Policy (README "Testing"): 0 missed mutants required; timeout-class mutants
// (infinite loops) count as caught — the timeout *is* the catch. cargo-mutants
// exits 2 on missed and 3 on timeouts, so exit 3 passes iff missed.txt is
// empty (codes don't combine; missed takes precedence, but re-check anyway).
const result = await $`cargo mutants -p dcap-verify`.nothrow();
const code = result.exitCode;

if (code === 3) {
  const missed = (await Bun.file("mutants.out/missed.txt")
    .text()
    .catch(() => "unreadable")).trim();
  if (missed === "") {
    console.log(
      "\x1b[33mtimeout-class mutants only — counted as caught (README policy)\x1b[0m"
    );
    process.exit(0);
  }
  console.error(`\x1b[31mmissed mutants:\n${missed}\x1b[0m`);
}
process.exit(code);
