// wasb gate for pi (>= 1.4): the agent may not settle while `wasb check --json` fails.
//
// Load it with `pi -e harness/pi/wasb-gate.ts`, or copy it to ~/.pi/agent/extensions/.
// Set WASB_BIN to an absolute path so a wasb planted earlier on PATH cannot answer for it.
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const WASB = process.env.WASB_BIN || "wasb";

// Escape cannot kill a command run from agent_before_settle (no run signal exists there),
// so a hung check is bounded by this timeout; a timeout counts as a failure.
const TIMEOUT_MS = 10 * 60 * 1000;

export default function (pi: ExtensionAPI) {
	pi.on("agent_before_settle", async (event, ctx) => {
		// "aborted": the human interrupted. "error": provider failure; continuing would spin on it.
		// Either way the run stops without passing, and the next prompt is gated again.
		if (event.outcome !== "completed") return;
		const failure = await check(pi, ctx.cwd, ctx.signal);
		if (!failure) return;
		return {
			entries: [...event.entries, { type: "custom_message", customType: "wasb-gate", display: true, content: failure }],
			continue: true,
		};
	});
}

// Returns undefined only when wasb exits 0 and reports pass: true. Anything else fails closed.
async function check(pi: ExtensionAPI, cwd: string, signal: AbortSignal | undefined): Promise<string | undefined> {
	let r: Awaited<ReturnType<ExtensionAPI["exec"]>>;
	try {
		r = await pi.exec(WASB, ["check", "--json"], { cwd, signal, timeout: TIMEOUT_MS });
	} catch (err) {
		return `wasb gate: could not run \`${WASB} check --json\`: ${String(err)}. You may not finish until it runs and passes.`;
	}
	let out: { pass?: unknown; diagnostics?: unknown } | null;
	try {
		out = JSON.parse(r.stdout);
	} catch {
		// pi.exec reports a missing binary as exit 1 with empty output.
		return [
			`wasb gate: \`${WASB} check --json\` printed no JSON (exit ${r.code}${r.killed ? ", killed or timed out" : ""}).`,
			"Is wasb installed (or WASB_BIN set)? You may not finish until it runs and passes.",
			r.stderr.trim() && `stderr:\n${r.stderr.trim()}`,
		]
			.filter(Boolean)
			.join("\n");
	}
	// A throw here would fail open (pi swallows handler errors), hence the optional chaining.
	if (r.code === 0 && out?.pass === true) return undefined;
	return [
		`wasb check failed (exit ${r.code}). You may not finish until \`wasb check --json\` passes.`,
		"Fix every diagnostic below; each has gate, element, path, line, message and fix.",
		"A fix that needs a change under .wasb/model/user/ is not yours to make: record it with `wasb propose` and say so.",
		"```json",
		JSON.stringify(out?.diagnostics ?? out, null, 2),
		"```",
	].join("\n");
}
