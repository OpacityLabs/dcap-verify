import { $ } from "bun";

type ShellPromise = ReturnType<typeof $>;

// Differential-tester harness for dcap-verify vs Intel QVL. See
// dcap-differ/FINDINGS.md. The crate is excluded from the workspace and needs
// libsgx_dcap_quoteverify.so.1 (host-side, no enclave). Not a mobile/default dep.

const MANIFEST = "dcap-differ/Cargo.toml";
const BIN = "dcap-differ/target/release/dcap-differ";
const SEED = "0xDCAF00000011";

// Recorded dangerous-polarity findings (FINDINGS.md), passed to every leg via
// --allow: a recorded case that fires counts as known-dangerous (CLEAN), one
// that stops firing counts as vanished (REVIEW), and anything unrecorded stays
// dangerous (REVIEW). Every leg therefore expects CLEAN, and any REVIEW means
// FINDINGS.md and this list must be updated together.
const ALLOW = "dcap-differ/known-dangerous.json";

// Exit-code contract of the binary (see pipeline::Tally): each invocation
// reports the run's verdict as its exit status, not just "the binary ran".
const EXIT_CLEAN = 0; // agreements, known deltas, dcap-stricter safe-direction, allowlisted dangerous
const EXIT_REVIEW = 10; // unrecorded dangerous divergence, or an allowlisted case that vanished
const EXIT_FAIL = 20; // dcap-panic or standing-mismatch — a real defect

const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;

const step = process.argv[2] ?? "all";
const iters = Number(process.argv[3] ?? "10000");
const runAll = step === "all";
// Per-leg output is captured and summarized to one line; VERBOSE=1 streams the
// binaries' full per-case tables instead, and any deviating leg is always
// dumped in full.
const verbose = !!process.env.VERBOSE;

function label(code: number): string {
  if (code === EXIT_CLEAN) return "CLEAN";
  if (code === EXIT_REVIEW) return "REVIEW";
  if (code === EXIT_FAIL) return "FAIL";
  return `exit ${code}`;
}

const deviations: string[] = [];

// Run one leg, expecting CLEAN. Prints a one-line summary on success and the
// leg's full output on any deviation.
async function leg(
  name: string,
  shell: ShellPromise,
  hint: string,
  summarize?: (text: string) => string
): Promise<void> {
  const r = await (verbose ? shell : shell.quiet()).nothrow();
  const text = `${r.stdout.toString()}${r.stderr.toString()}`;
  if (r.exitCode === EXIT_CLEAN) {
    const summary = summarize?.(text) ?? resultLine(text);
    console.log(`${green("✓")} ${name} — ${summary}`);
  } else {
    if (!verbose) console.log(text);
    console.log(`${red("✗")} ${name} — ${label(r.exitCode)}`);
    deviations.push(`${name}: got ${label(r.exitCode)} — ${hint}`);
  }
}

function resultLine(text: string): string {
  const line = text.split("\n").find((l) => l.startsWith("RESULT: "));
  return line?.replace("RESULT: ", "") ?? "CLEAN";
}

// Just the bucket tallies from the RESULT line, without the prose.
function tallies(text: string): string {
  const line = resultLine(text);
  const bracket = line.match(/\[(.*)\]/);
  return bracket ? `CLEAN [${bracket[1]}]` : line;
}

try {
  if (!verbose) console.log(dim("dcap-differ vs Intel QVL (VERBOSE=1 for full per-case output)"));
  const build = await (verbose
    ? $`cargo build --release --manifest-path ${MANIFEST}`
    : $`cargo build --release --manifest-path ${MANIFEST}`.quiet()
  ).nothrow();
  if (build.exitCode !== 0) {
    if (!verbose) console.log(`${build.stdout.toString()}${build.stderr.toString()}`);
    throw Object.assign(new Error("build failed"), { exitCode: build.exitCode });
  }

  if (runAll || step === "calibrate") {
    await leg(
      "calibrate",
      $`${BIN} calibrate`,
      "the QVL marshaling is no longer trusted; nothing downstream is meaningful",
      (text) =>
        text
          .split("\n")
          .find((l) => l.startsWith("chosen marshaling config"))
          ?.trim() ?? "marshaling gate ok"
    );
  }

  if (runAll || step === "fixtures") {
    await leg(
      "fixtures (oracle corpus)",
      $`${BIN} fixtures --allow ${ALLOW}`,
      "the oracle corpus has no recorded dangerous case; triage the dumps into FINDINGS.md",
      tallies
    );

    await leg(
      "fixtures (corpus-committed)",
      $`${BIN} fixtures --root dcap-differ/corpus-committed --allow ${ALLOW}`,
      "an unrecorded divergence (or a vanished recorded one) on genuine Intel-signed artifacts",
      tallies
    );

    // The full recombination corpus is regenerable (Intel PCS) and gitignored;
    // run it only if it's already present, so the task never needs the network.
    if (await Bun.file("dcap-differ/corpus/control-fresh-eval19/meta.json").exists()) {
      await leg(
        "fixtures (full corpus, local)",
        $`${BIN} fixtures --root dcap-differ/corpus --allow ${ALLOW}`,
        "an unrecorded divergence in the regenerated corpus — triage into FINDINGS.md",
        tallies
      );
    } else {
      console.log(
        dim(
          "- fixtures (full corpus) skipped — not generated; run `python3 dcap-differ/tools/build_recombination_corpus.py` to fetch it"
        )
      );
    }
  }

  if (runAll || step === "replay") {
    const allow = await Bun.file(ALLOW).json();
    const results: string[] = [];
    for (const k of allow.sweep) {
      const r =
        await $`${BIN} sweep --seed ${k.seed} --iters 1 --only-iter ${k.iter} --allow ${ALLOW} --out dcap-differ/reports/mise-replay`
          .quiet()
          .nothrow();
      if (r.exitCode !== EXIT_CLEAN) {
        console.log(`${r.stdout.toString()}${r.stderr.toString()}`);
        deviations.push(
          `replay ${k.finding} (seed ${k.seed}, iter ${k.iter}): got ${label(r.exitCode)} — the recorded case vanished; if it was deliberately fixed, update FINDINGS.md and known-dangerous.json together`
        );
        results.push(`${k.finding}@${k.iter}:${label(r.exitCode)}`);
      }
    }
    const total = allow.sweep.length;
    if (results.length === 0) {
      console.log(`${green("✓")} replay — ${total}/${total} recorded findings reproduce`);
    } else {
      console.log(`${red("✗")} replay — failed: ${results.join(", ")}`);
    }
  }

  if (runAll || step === "sweep") {
    await leg(
      `sweep (${iters} iters, seed ${SEED})`,
      $`${BIN} sweep --iters ${iters} --seed ${SEED} --allow ${ALLOW} --out dcap-differ/reports/mise-run`,
      "a new or vanished divergence — triage it into FINDINGS.md before shipping",
      tallies
    );
  }
} catch (error) {
  console.error(`\n${red("✗ dcap-differ: could not run (build/setup error)")}`);
  process.exit((error as { exitCode?: number }).exitCode ?? 1);
}

console.log();
if (deviations.length > 0) {
  console.log(red("✗ DEVIATION — the differ did not match its recorded expectations:"));
  for (const d of deviations) {
    console.log(`  - ${d}`);
  }
  process.exit(1);
} else {
  console.log(
    green(
      "✓ EXPECTED — every leg CLEAN (recorded FINDINGS.md cases reproduce; no new dangerous divergence, no panic, no standing mismatch)."
    )
  );
}
