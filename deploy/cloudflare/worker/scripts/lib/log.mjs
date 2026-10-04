// @ts-check
// Line-oriented progress output in the same style as the shell scripts:
//   ok      <what>   nothing to change
//   create  <what>   a resource was created (plan mode prints "create?": would be)
//   update  <what>   an existing resource was (would be) changed
//   delete  <what>   a resource was (would be) removed
//   warn    <what>   works, but needs attention
//   skip    <what>   a step that does not apply
//   fail    <what>   a check failed

/** @typedef {"ok" | "create" | "update" | "delete" | "warn" | "skip" | "fail"} Tag */
/** @typedef {{ tag: Tag, message: string }} Action */

/**
 * @param {{ write?: (s: string) => void, dryRun?: boolean }} [options]
 */
export function createLogger(options = {}) {
  const write = options.write ?? ((s) => process.stdout.write(s));
  const dryRun = options.dryRun ?? false;
  /** @type {Action[]} */
  const actions = [];
  /**
   * @param {Tag} tag
   * @param {string} message
   */
  const record = (tag, message) => {
    actions.push({ tag, message });
    const mutating = tag === "create" || tag === "update" || tag === "delete";
    const label = dryRun && mutating ? `${tag}?` : tag;
    write(`${label.padEnd(7)} ${message}\n`);
  };
  return {
    dryRun,
    actions,
    /** @param {string} title */
    step: (title) => write(`\n==> ${title}\n`),
    /** @param {string} m */ ok: (m) => record("ok", m),
    /** @param {string} m */ create: (m) => record("create", m),
    /** @param {string} m */ update: (m) => record("update", m),
    /** @param {string} m */ remove: (m) => record("delete", m),
    /** @param {string} m */ warn: (m) => record("warn", m),
    /** @param {string} m */ skip: (m) => record("skip", m),
    /** @param {string} m */ fail: (m) => record("fail", m),
    /** @param {string} m */ info: (m) => write(`${m}\n`),
  };
}

/** @typedef {ReturnType<typeof createLogger>} Logger */
