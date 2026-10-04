// @ts-check
// Idempotent "ensure" steps for every Cloudflare resource the edge stack needs.
// Each step reads first and changes only what differs, so `up` can be re-run at
// any time. In plan mode (ctx.log.dryRun) nothing is written: steps report what
// they would do and return placeholders for ids that do not exist yet.

import { CloudflareApiError } from "./cloudflare.mjs";
import { EdgeError, deepEqual, isSubset } from "./util.mjs";

/**
 * @typedef {object} Ctx
 * @property {import("./cloudflare.mjs").CloudflareClient} api
 * @property {import("./log.mjs").Logger} log
 * @property {import("./state.mjs").EdgeState} state
 * @property {() => void} persist   saves the state file (no-op in plan mode)
 * @property {string} accountId
 * @property {() => number} [now]
 */

/** Stands in for an id that only exists after `up` creates the resource. */
export const PENDING = "<created by up>";

/** Token permission names, for 401/403 hints and the README. */
export const NEED = {
  accounts: "Account Settings: Read (or pass --account)",
  zone: "Zone: Read",
  dns: "DNS: Edit",
  tunnel: "Cloudflare Tunnel: Edit",
  org: "Access: Organizations, Identity Providers, and Groups: Read",
  orgEdit: "Access: Organizations, Identity Providers, and Groups: Edit",
  apps: "Access: Apps and Policies: Edit",
  tokens: "Access: Service Tokens: Edit",
  kv: "Workers KV Storage: Edit",
  d1: "D1: Edit",
  workers: "Workers Scripts: Edit",
};

/** @param {Ctx} ctx */
const acct = (ctx) => `/accounts/${ctx.accountId}`;

/**
 * @param {Ctx} ctx
 * @param {string} key
 * @param {string} id
 */
function remember(ctx, key, id, created = false) {
  ctx.state.ids[key] = id;
  if (created) ctx.state.created[key] = true;
  ctx.persist();
}

// -- account, zone, Zero Trust ------------------------------------------------

/**
 * @param {Pick<Ctx, "api" | "log">} ctx
 * @param {string | undefined} explicit
 * @returns {Promise<string>}
 */
export async function resolveAccount(ctx, explicit) {
  if (explicit) {
    ctx.log.ok(`account ${explicit}`);
    return explicit;
  }
  const accounts = await ctx.api.list("/accounts", { need: NEED.accounts });
  if (accounts.length === 1) {
    ctx.log.ok(`account ${accounts[0].name} (${accounts[0].id})`);
    return accounts[0].id;
  }
  if (accounts.length === 0) throw new EdgeError("the API token can see no account; pass --account <id>");
  const names = accounts.map((a) => `${a.id} (${a.name})`).join(", ");
  throw new EdgeError(`the API token can see ${accounts.length} accounts; pass --account with one of: ${names}`);
}

/**
 * @param {Ctx} ctx
 * @param {string} zone
 * @returns {Promise<string>}
 */
export async function resolveZone(ctx, zone) {
  const zones = (
    await ctx.api.list("/zones", { query: { name: zone, "account.id": ctx.accountId }, need: NEED.zone })
  ).filter((z) => z.name === zone);
  const found = zones[0];
  if (!found) {
    throw new EdgeError(`zone ${zone} is not in account ${ctx.accountId} (or the token lacks "${NEED.zone}")`);
  }
  if (found.status !== "active") {
    ctx.log.warn(`zone ${zone} is ${found.status}, not active: hostnames will not resolve until its nameservers point at Cloudflare`);
  } else {
    ctx.log.ok(`zone ${zone} (${found.id})`);
  }
  return found.id;
}

/**
 * Reads the Zero Trust organization (required: Access protects the origin) and
 * optionally turns on strict service token authentication, which stops Access
 * from answering a valid service token with a CF_Authorization cookie.
 * @param {Ctx} ctx
 * @param {{ strict: boolean }} opts
 * @returns {Promise<{ teamDomain: string }>}
 */
export async function ensureZeroTrust(ctx, opts) {
  /** @type {any} */
  let org;
  try {
    org = await ctx.api.get(`${acct(ctx)}/access/organizations`, { need: NEED.org });
  } catch (err) {
    if (err instanceof CloudflareApiError && err.status === 404) {
      throw new EdgeError(
        "Zero Trust is not set up on this account. Open https://one.dash.cloudflare.com once, pick a team name " +
          "(the Free plan is enough), then re-run.",
      );
    }
    throw err;
  }
  if (!org?.auth_domain) throw new EdgeError("the Zero Trust organization has no team domain (auth_domain)");
  const teamDomain = `https://${org.auth_domain}`;
  ctx.log.ok(`Zero Trust team ${teamDomain}`);

  const strict = org.strict_service_token_auth;
  if (strict === true) {
    ctx.log.ok("strict service token authentication is on");
  } else if (opts.strict) {
    if (!ctx.log.dryRun) {
      await ctx.api.patch(`${acct(ctx)}/access/organizations`, {
        body: { strict_service_token_auth: true },
        need: NEED.orgEdit,
      });
    }
    ctx.log.update("strict service token authentication: on (organization-wide)");
  } else {
    ctx.log.warn(
      `strict service token authentication is ${strict === false ? "off" : "not reported"}: Access may answer ` +
        "the Worker's service token with a CF_Authorization cookie (the Worker drops it). Re-run with " +
        "--strict-service-tokens to turn it on organization-wide (Cloudflare's recommended setting).",
    );
  }
  return { teamDomain };
}

// -- tunnel --------------------------------------------------------------------

/**
 * Finds or creates the remotely-managed tunnel and returns its connector token.
 * @param {Ctx} ctx
 * @param {string} name
 * @returns {Promise<{ id: string, token: string | null }>}
 */
export async function ensureTunnel(ctx, name) {
  const found = (
    await ctx.api.list(`${acct(ctx)}/cfd_tunnel`, { query: { name, is_deleted: false }, need: NEED.tunnel })
  ).filter((t) => t.name === name && !t.deleted_at);
  if (found.length > 1) {
    throw new EdgeError(`${found.length} tunnels are named ${name}; delete the extras or pass --tunnel-name`);
  }
  let tunnel = found[0];
  if (tunnel) {
    if (tunnel.config_src !== "cloudflare") {
      throw new EdgeError(
        `tunnel ${name} is locally managed (config file); this command manages remotely-managed tunnels. ` +
          "Pass --tunnel-name <new name>, or keep using the config overlay by hand.",
      );
    }
    ctx.log.ok(`tunnel ${name} (${tunnel.id}, status ${tunnel.status ?? "unknown"})`);
    remember(ctx, "tunnel", tunnel.id);
  } else if (ctx.log.dryRun) {
    ctx.log.create(`tunnel ${name} (remotely managed)`);
    return { id: PENDING, token: null };
  } else {
    tunnel = await ctx.api.post(`${acct(ctx)}/cfd_tunnel`, {
      body: { name, config_src: "cloudflare" },
      need: NEED.tunnel,
    });
    ctx.log.create(`tunnel ${name} (${tunnel.id})`);
    remember(ctx, "tunnel", tunnel.id, true);
  }
  if (ctx.log.dryRun) return { id: tunnel.id, token: null };
  const token =
    typeof tunnel.token === "string" && tunnel.token
      ? tunnel.token
      : await ctx.api.get(`${acct(ctx)}/cfd_tunnel/${tunnel.id}/token`, { need: NEED.tunnel });
  return { id: tunnel.id, token };
}

/**
 * Returns `existing` with exactly one rule for `rule.hostname` (all paths) and a
 * catch-all at the end. Rules for other hostnames, and an existing rule's extra
 * fields when its service already matches, are kept as they are.
 * @param {any[]} existing
 * @param {{ hostname: string, service: string, originRequest?: object }} rule
 * @returns {any[]}
 */
export function mergeIngress(existing, rule) {
  /** @param {any} r */
  const isCatchAll = (r) => !r.hostname && !r.path;
  /** @param {any} r */
  const isOurs = (r) => typeof r.hostname === "string" && r.hostname.toLowerCase() === rule.hostname && !r.path;
  const catchAll = existing.find(isCatchAll) ?? { service: "http_status:404" };
  let placed = false;
  const out = [];
  for (const r of existing) {
    if (isCatchAll(r)) continue;
    if (isOurs(r)) {
      if (placed) continue;
      out.push(r.service === rule.service ? r : { ...r, service: rule.service });
      placed = true;
    } else {
      out.push(r);
    }
  }
  if (!placed) out.push(rule);
  out.push(catchAll);
  return out;
}

/**
 * @param {Ctx} ctx
 * @param {string} tunnelId
 * @param {string} hostname
 * @param {string} service
 */
export async function ensureIngress(ctx, tunnelId, hostname, service) {
  if (tunnelId === PENDING) {
    ctx.log.create(`tunnel route ${hostname} -> ${service}`);
    return;
  }
  const current = (await ctx.api.get(`${acct(ctx)}/cfd_tunnel/${tunnelId}/configurations`, { need: NEED.tunnel }))
    ?.config ?? {};
  const ingress = Array.isArray(current.ingress) ? current.ingress : [];
  const desired = mergeIngress(ingress, { hostname, service, originRequest: {} });
  if (deepEqual(ingress, desired)) {
    ctx.log.ok(`tunnel route ${hostname} -> ${service}`);
    return;
  }
  if (!ctx.log.dryRun) {
    await ctx.api.put(`${acct(ctx)}/cfd_tunnel/${tunnelId}/configurations`, {
      body: { config: { ...current, ingress: desired } },
      need: NEED.tunnel,
    });
  }
  ctx.log.update(`tunnel route ${hostname} -> ${service}`);
}

/**
 * The tunnel's connection status ("healthy", "degraded", "inactive", "down").
 * @param {Ctx} ctx
 * @param {string} tunnelId
 * @returns {Promise<string>}
 */
export async function tunnelStatus(ctx, tunnelId) {
  const tunnel = await ctx.api.get(`${acct(ctx)}/cfd_tunnel/${tunnelId}`, { need: NEED.tunnel });
  return String(tunnel?.status ?? "unknown");
}

// -- DNS -------------------------------------------------------------------------

/**
 * Proxied CNAME `name` -> `target`. Refuses to touch a record that points elsewhere.
 * @param {Ctx} ctx
 * @param {string} zoneId
 * @param {string} name
 * @param {string} target
 */
export async function ensureCname(ctx, zoneId, name, target) {
  const records = (
    await ctx.api.list(`/zones/${zoneId}/dns_records`, { query: { name }, need: NEED.dns })
  ).filter((r) => String(r.name).toLowerCase() === name);
  if (records.length === 0) {
    if (!ctx.log.dryRun) {
      const record = await ctx.api.post(`/zones/${zoneId}/dns_records`, {
        body: { type: "CNAME", name, content: target, proxied: true, ttl: 1, comment: "airweave edge gateway tunnel" },
        need: NEED.dns,
      });
      remember(ctx, "dns:origin", record.id, true);
    }
    ctx.log.create(`DNS ${name} CNAME ${target} (proxied)`);
    return;
  }
  const [record] = records;
  if (records.length === 1 && record.type === "CNAME" && String(record.content).toLowerCase() === target) {
    remember(ctx, "dns:origin", record.id);
    if (record.proxied) {
      ctx.log.ok(`DNS ${name} CNAME ${target} (proxied)`);
      return;
    }
    if (!ctx.log.dryRun) {
      await ctx.api.patch(`/zones/${zoneId}/dns_records/${record.id}`, { body: { proxied: true }, need: NEED.dns });
    }
    ctx.log.update(`DNS ${name}: proxied (Access only applies to proxied records)`);
    return;
  }
  const have = records.map((r) => `${r.type} ${r.content}`).join(", ");
  throw new EdgeError(
    `${name} already has DNS record(s) [${have}], not CNAME ${target}. Delete them in the dashboard ` +
      "(DNS > Records) or pass --origin-host <another name>.",
  );
}

// -- Access: service token, policies, applications -------------------------------

/**
 * The Worker's service token for the origin. Its secret is only shown at creation,
 * so it lives in the state file; with a token but no stored secret, the secret is
 * rotated (old one revoked) rather than a duplicate token created.
 * @param {Ctx} ctx
 * @param {string} name
 * @returns {Promise<{ id: string, clientId: string, clientSecret: string }>}
 */
export async function ensureServiceToken(ctx, name) {
  const matches = (await ctx.api.list(`${acct(ctx)}/access/service_tokens`, { need: NEED.tokens })).filter(
    (t) => t.name === name,
  );
  if (matches.length > 1) throw new EdgeError(`${matches.length} service tokens are named "${name}"; delete the extras`);
  /** @type {{ id: string, client_id: string, expires_at?: string } | undefined} */
  const existing = matches[0] && { id: matches[0].id, client_id: matches[0].client_id, expires_at: matches[0].expires_at };
  const known = ctx.state.serviceToken;
  if (!existing) {
    if (ctx.log.dryRun) {
      ctx.log.create(`Access service token "${name}" (1 year)`);
      return { id: PENDING, clientId: PENDING, clientSecret: PENDING };
    }
    const created = await ctx.api.post(`${acct(ctx)}/access/service_tokens`, {
      body: { name, duration: "8760h" },
      need: NEED.tokens,
    });
    const entryId = String(created.id);
    ctx.state.serviceToken = { id: entryId, clientId: created.client_id, clientSecret: created.client_secret };
    remember(ctx, "service-token", entryId, true);
    ctx.log.create(`Access service token "${name}" (id ${entryId})`);
    return ctx.state.serviceToken;
  }
  const entryId = existing.id;
  if (known && known.id === entryId && known.clientSecret) {
    ctx.log.ok(`Access service token "${name}" (id ${entryId})`);
    remember(ctx, "service-token", entryId);
  } else {
    if (ctx.log.dryRun) {
      ctx.log.update(`Access service token "${name}": rotate the secret (it is not in the state file)`);
      return { id: entryId, clientId: existing.client_id, clientSecret: PENDING };
    }
    const rotated = await ctx.api.post(`${acct(ctx)}/access/service_tokens/${entryId}/rotate`, {
      body: {},
      need: NEED.tokens,
    });
    ctx.state.serviceToken = { id: entryId, clientId: existing.client_id, clientSecret: rotated.client_secret };
    remember(ctx, "service-token", entryId);
    ctx.log.update(`Access service token "${name}": secret rotated (the state file had none; old secret revoked)`);
  }
  const now = ctx.now ? ctx.now() : Date.now();
  const expires = Date.parse(existing.expires_at ?? "");
  if (Number.isFinite(expires) && expires - now < 30 * 24 * 3600 * 1000) {
    if (!ctx.log.dryRun) {
      await ctx.api.post(`${acct(ctx)}/access/service_tokens/${entryId}/refresh`, { body: {}, need: NEED.tokens });
    }
    ctx.log.update(`Access service token "${name}": renewed (it expired or expires within 30 days)`);
  }
  return /** @type {{ id: string, clientId: string, clientSecret: string }} */ (ctx.state.serviceToken);
}

/**
 * A reusable Access policy, matched by name.
 * @param {Ctx} ctx
 * @param {string} key   state key suffix, e.g. "origin"
 * @param {{ name: string, decision: string, include: object[] }} spec
 * @returns {Promise<string>}  policy id
 */
export async function ensurePolicy(ctx, key, spec) {
  const desired = { name: spec.name, decision: spec.decision, include: spec.include, exclude: [], require: [] };
  const found = (await ctx.api.list(`${acct(ctx)}/access/policies`, { need: NEED.apps })).filter(
    (p) => p.name === spec.name,
  );
  if (found.length > 1) throw new EdgeError(`${found.length} Access policies are named "${spec.name}"`);
  const policy = found[0];
  const stateKey = `policy:${key}`;
  if (!policy) {
    if (ctx.log.dryRun) {
      ctx.log.create(`Access policy "${spec.name}" (${spec.decision})`);
      return PENDING;
    }
    const created = await ctx.api.post(`${acct(ctx)}/access/policies`, { body: desired, need: NEED.apps });
    remember(ctx, stateKey, created.id, true);
    ctx.log.create(`Access policy "${spec.name}" (${spec.decision})`);
    return created.id;
  }
  remember(ctx, stateKey, policy.id);
  const same =
    policy.decision === spec.decision &&
    isSubset(spec.include, policy.include ?? []) &&
    (policy.exclude ?? []).length === 0 &&
    (policy.require ?? []).length === 0;
  if (same) {
    ctx.log.ok(`Access policy "${spec.name}"`);
  } else {
    if (!ctx.log.dryRun) {
      await ctx.api.put(`${acct(ctx)}/access/policies/${policy.id}`, { body: desired, need: NEED.apps });
    }
    ctx.log.update(`Access policy "${spec.name}" (${spec.decision})`);
  }
  return policy.id;
}

/** Fields an Access application GET returns that a PUT must not send back. */
const APP_READ_ONLY = ["id", "uid", "aud", "created_at", "updated_at", "policies"];

/**
 * A self-hosted Access application on `domain` (a hostname, or hostname/path)
 * that has `policyIds` attached. Policies someone else attached are kept; for
 * the origin application they are reported, since any of them can let a
 * request reach the backend without passing the Worker.
 * @param {Ctx} ctx
 * @param {string} key
 * @param {{ name: string, domain: string, policyIds: string[], warnOnExtraPolicies?: boolean }} spec
 * @returns {Promise<{ id: string, aud: string }>}
 */
export async function ensureAccessApp(ctx, key, spec) {
  /** @param {unknown} d */
  const same = (d) => typeof d === "string" && d.toLowerCase().replace(/\/$/, "") === spec.domain;
  const found = (await ctx.api.list(`${acct(ctx)}/access/apps`, { need: NEED.apps })).filter(
    (app) =>
      same(app.domain) ||
      (app.self_hosted_domains ?? []).some(same) ||
      (app.destinations ?? []).some((/** @type {any} */ d) => same(d?.uri)),
  );
  if (found.length > 1) {
    throw new EdgeError(`${found.length} Access applications cover ${spec.domain}; keep one`);
  }
  const stateKey = `app:${key}`;
  const app = found[0];
  if (!app) {
    if (ctx.log.dryRun) {
      ctx.log.create(`Access application "${spec.name}" on ${spec.domain}`);
      return { id: PENDING, aud: PENDING };
    }
    const created = await ctx.api.post(`${acct(ctx)}/access/apps`, {
      body: {
        name: spec.name,
        type: "self_hosted",
        domain: spec.domain,
        session_duration: "24h",
        app_launcher_visible: false,
        service_auth_401_redirect: true,
        policies: spec.policyIds.map((id, i) => ({ id, precedence: i + 1 })),
      },
      need: NEED.apps,
    });
    remember(ctx, stateKey, created.id, true);
    ctx.log.create(`Access application "${spec.name}" on ${spec.domain}`);
    return { id: created.id, aud: created.aud };
  }
  remember(ctx, stateKey, app.id);
  /** @type {{ id: string, precedence?: number, name?: string, decision?: string }[]} */
  const attached = Array.isArray(app.policies) ? app.policies : [];
  const missing = spec.policyIds.filter((id) => !attached.some((p) => p.id === id));
  if (spec.warnOnExtraPolicies) {
    for (const p of attached.filter((p) => !spec.policyIds.includes(p.id))) {
      ctx.log.warn(
        `Access application on ${spec.domain} also has policy "${p.name ?? p.id}" (${p.decision ?? "?"}); ` +
          "anything it admits reaches the backend without passing the Worker",
      );
    }
  }
  if (missing.length === 0) {
    ctx.log.ok(`Access application "${app.name}" on ${spec.domain}`);
    return { id: app.id, aud: app.aud };
  }
  if (!ctx.log.dryRun) {
    const body = Object.fromEntries(Object.entries(app).filter(([k]) => !APP_READ_ONLY.includes(k)));
    const refs = attached.map((p, i) => ({ id: p.id, precedence: p.precedence ?? i + 1 }));
    let next = refs.reduce((max, r) => Math.max(max, r.precedence), 0);
    for (const id of missing) refs.push({ id, precedence: ++next });
    await ctx.api.put(`${acct(ctx)}/access/apps/${app.id}`, { body: { ...body, policies: refs }, need: NEED.apps });
  }
  ctx.log.update(`Access application "${app.name}" on ${spec.domain}: attach ${missing.length} policy(ies)`);
  return { id: app.id, aud: app.aud };
}

// -- Worker bindings and hostname -----------------------------------------------------

/**
 * @param {Ctx} ctx
 * @param {string} title
 * @returns {Promise<string>}
 */
export async function ensureKvNamespace(ctx, title) {
  const found = (
    await ctx.api.list(`${acct(ctx)}/storage/kv/namespaces`, { perPage: 100, need: NEED.kv })
  ).filter((n) => n.title === title);
  if (found[0]) {
    ctx.log.ok(`KV namespace ${title} (${found[0].id})`);
    remember(ctx, "kv", found[0].id);
    return found[0].id;
  }
  if (ctx.log.dryRun) {
    ctx.log.create(`KV namespace ${title}`);
    return PENDING;
  }
  const created = await ctx.api.post(`${acct(ctx)}/storage/kv/namespaces`, { body: { title }, need: NEED.kv });
  remember(ctx, "kv", created.id, true);
  ctx.log.create(`KV namespace ${title} (${created.id})`);
  return created.id;
}

/**
 * @param {Ctx} ctx
 * @param {string} name
 * @returns {Promise<string>}
 */
export async function ensureD1(ctx, name) {
  const found = (await ctx.api.list(`${acct(ctx)}/d1/database`, { query: { name }, need: NEED.d1 })).filter(
    (d) => d.name === name,
  );
  if (found[0]) {
    ctx.log.ok(`D1 database ${name} (${found[0].uuid})`);
    remember(ctx, "d1", found[0].uuid);
    return found[0].uuid;
  }
  if (ctx.log.dryRun) {
    ctx.log.create(`D1 database ${name}`);
    return PENDING;
  }
  const created = await ctx.api.post(`${acct(ctx)}/d1/database`, { body: { name }, need: NEED.d1 });
  remember(ctx, "d1", created.uuid, true);
  ctx.log.create(`D1 database ${name} (${created.uuid})`);
  return created.uuid;
}

/**
 * A Workers Custom Domain cannot be created over an existing DNS record, and
 * must not be taken from another Worker. Check before `wrangler deploy` does.
 * @param {Ctx} ctx
 * @param {string} zoneId
 * @param {string} host
 * @param {string} worker
 */
export async function checkCustomDomain(ctx, zoneId, host, worker) {
  const domains = (
    await ctx.api.list(`${acct(ctx)}/workers/domains`, { query: { hostname: host }, need: NEED.workers })
  ).filter((d) => d.hostname === host);
  const attached = domains[0];
  if (attached) {
    if (attached.service !== worker) {
      throw new EdgeError(`${host} is the Custom Domain of Worker "${attached.service}"; pass --api-host <another name>`);
    }
    ctx.log.ok(`Custom Domain ${host} -> Worker ${worker}`);
    return;
  }
  const records = (
    await ctx.api.list(`/zones/${zoneId}/dns_records`, { query: { name: host }, need: NEED.dns })
  ).filter((r) => String(r.name).toLowerCase() === host);
  if (records.length) {
    const have = records.map((r) => `${r.type} ${r.content}`).join(", ");
    throw new EdgeError(
      `${host} already has DNS record(s) [${have}]; a Workers Custom Domain cannot be created over them. ` +
        "Delete them or pass --api-host <another name>.",
    );
  }
  ctx.log.create(`Custom Domain ${host} -> Worker ${worker} (created by wrangler deploy)`);
}

/**
 * @param {Ctx} ctx
 * @param {string} name
 */
export async function workerExists(ctx, name) {
  const scripts = await ctx.api.list(`${acct(ctx)}/workers/scripts`, { need: NEED.workers });
  return scripts.some((s) => s.id === name);
}

// -- teardown ---------------------------------------------------------------------

/**
 * Deletes one resource this tool created, tolerating "already gone".
 * @param {Ctx} ctx
 * @param {string} key
 * @param {string} label
 * @param {string} path
 */
export async function deleteCreated(ctx, key, label, path) {
  const id = ctx.state.ids[key];
  if (!ctx.state.created[key] || !id) return;
  if (!ctx.log.dryRun) {
    try {
      await ctx.api.del(path.replace("{id}", id));
    } catch (err) {
      if (!(err instanceof CloudflareApiError && err.status === 404)) throw err;
    }
    delete ctx.state.created[key];
    delete ctx.state.ids[key];
    ctx.persist();
  }
  ctx.log.remove(`${label} (${id})`);
}
