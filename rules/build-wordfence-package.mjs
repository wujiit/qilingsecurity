#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const PACKAGE_ID = 'qilingsecurity-rules';
const DEFAULT_SIGNER = 'qiling-official-v1';
const DEFAULT_ENDPOINT_BASE = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities';
const DEFAULT_MAX_ITEMS = 5000;
const DOCS_URL = 'https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/';
const TERMS_URL = 'https://www.wordfence.com/wfi-community-edition-terms-and-conditions/';
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const BUILTIN_RULE_DEFAULTS = {
  code_vulnerability_patterns: {
    RCE: '',
    SSRF: '',
    WRITE: '',
  },
  component_vulnerability_feed: [],
  scan_api_endpoints: {
    '/wp-json/wp/v2/users': '',
    '/xmlrpc.php': '',
    '/wp-sitemap-users-1.xml': '',
  },
  dark_link_patterns: [],
  upload_image_extensions: [],
  upload_svg_script_regex: '',
  upload_active_script_regex: '',
  persistence_safe_high_frequency_hooks: [],
  persistence_suspicious_keywords: [],
  persistence_suspicious_hook_regex: '',
  persistence_file_exec_regex: '',
  db_suspicious_option_name_patterns: [],
  db_suspicious_option_value_patterns: [],
  db_critical_option_keywords: [],
};

main().catch((error) => {
  console.error(`[build-wordfence-package] ${error.message}`);
  process.exit(1);
});

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.help) {
    printHelp();
    return;
  }

  if (!options.out) {
    throw new Error('Missing required option: --out <file>');
  }

  if (!options.privateKey) {
    throw new Error('Missing required option: --private-key <pem>');
  }

  const pluginVersion = options.minPluginVersion || detectPluginVersion();
  const feed = options.feedFile
    ? readJsonFile(options.feedFile)
    : await fetchWordfenceFeed(options.feedType, options.apiKey, options.timeoutMs);

  const entries = buildComponentFeed(feed, {
    includeInformational: options.includeInformational,
    componentTypes: options.componentTypes,
    maxItems: options.maxItems,
    feedType: options.feedType,
  });

  if (entries.length === 0) {
    throw new Error('No component vulnerability entries were generated from the provided Wordfence feed');
  }

  const version = options.version || buildDefaultVersion();
  const label =
    options.label || `Qiling Security Wordfence ${options.feedType} ${new Date().toISOString().slice(0, 10)}`;
  const baseRules = loadBaseRules(options.baseTemplate);

  const rules = sanitizeRulesForPlugin({
    ...baseRules,
    component_vulnerability_feed: entries,
  });

  const componentEntryCount = Array.isArray(rules.component_vulnerability_feed) ? rules.component_vulnerability_feed.length : 0;

  if (componentEntryCount === 0) {
    throw new Error('No usable component vulnerability entries remained after Qiling rule sanitization');
  }

  const rulesSha256 = sha256(normalizeForHash(rules));
  const privateKey = fs.readFileSync(options.privateKey, 'utf8');
  const rulesSignature = signPayload(
    {
      package_id: PACKAGE_ID,
      version,
      min_plugin_version: pluginVersion,
      rules_sha256: rulesSha256,
    },
    privateKey
  );

  const payload = {
    package_id: PACKAGE_ID,
    version,
    label,
    min_plugin_version: pluginVersion,
    rules_sha256: rulesSha256,
    signer: options.signer,
    rules_signature: rulesSignature,
    source_metadata: {
      provider: 'wordfence',
      feed_type: options.feedType,
      docs_url: DOCS_URL,
      terms_url: TERMS_URL,
      fetched_at: new Date().toISOString(),
      generated_by: 'build-wordfence-package.mjs',
      component_entry_count: componentEntryCount,
      note: 'This package contains condensed vulnerability detection metadata derived from the Wordfence Intelligence feed for Qiling Security component matching.',
      base_template: options.baseTemplate,
    },
    rules,
  };

  fs.writeFileSync(options.out, JSON.stringify(payload, null, 2) + '\n', 'utf8');

  console.log(`Output: ${options.out}`);
  console.log(`Feed: ${options.feedType}`);
  console.log(`Entries: ${entries.length}`);
  console.log(`Base template: ${options.baseTemplate}`);
  console.log(`rules_sha256: ${rulesSha256}`);
  console.log(`signer: ${options.signer}`);
}

function parseArgs(argv) {
  const options = {
    help: false,
    apiKey: process.env.WORDFENCE_API_KEY || '',
    feedFile: '',
    feedType: 'production',
    baseTemplate: path.resolve(SCRIPT_DIR, 'package-template.json'),
    out: '',
    privateKey: '',
    signer: DEFAULT_SIGNER,
    version: '',
    label: '',
    minPluginVersion: '',
    timeoutMs: 30000,
    includeInformational: false,
    componentTypes: new Set(['plugin', 'theme']),
    maxItems: DEFAULT_MAX_ITEMS,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--help' || arg === '-h') {
      options.help = true;
      continue;
    }

    if (!arg.startsWith('--')) {
      throw new Error(`Unknown argument: ${arg}`);
    }

    const [rawKey, inlineValue] = arg.split('=', 2);
    const key = rawKey.slice(2);
    const value = inlineValue ?? argv[i + 1];

    switch (key) {
      case 'api-key':
        options.apiKey = String(value || '');
        if (inlineValue === undefined) i += 1;
        break;
      case 'feed-file':
        options.feedFile = resolvePath(value);
        if (inlineValue === undefined) i += 1;
        break;
      case 'feed-type':
        options.feedType = normalizeFeedType(value);
        if (inlineValue === undefined) i += 1;
        break;
      case 'base-template':
        options.baseTemplate = resolvePath(value);
        if (inlineValue === undefined) i += 1;
        break;
      case 'out':
        options.out = resolvePath(value);
        if (inlineValue === undefined) i += 1;
        break;
      case 'private-key':
        options.privateKey = resolvePath(value);
        if (inlineValue === undefined) i += 1;
        break;
      case 'signer':
        options.signer = String(value || DEFAULT_SIGNER);
        if (inlineValue === undefined) i += 1;
        break;
      case 'version':
        options.version = String(value || '');
        if (inlineValue === undefined) i += 1;
        break;
      case 'label':
        options.label = String(value || '');
        if (inlineValue === undefined) i += 1;
        break;
      case 'min-plugin-version':
        options.minPluginVersion = String(value || '');
        if (inlineValue === undefined) i += 1;
        break;
      case 'timeout-ms':
        options.timeoutMs = Math.max(1000, Number.parseInt(String(value || '30000'), 10) || 30000);
        if (inlineValue === undefined) i += 1;
        break;
      case 'component-types':
        options.componentTypes = normalizeComponentTypes(String(value || 'plugin,theme'));
        if (inlineValue === undefined) i += 1;
        break;
      case 'max-items':
        options.maxItems = Math.max(1, Number.parseInt(String(value || DEFAULT_MAX_ITEMS), 10) || DEFAULT_MAX_ITEMS);
        if (inlineValue === undefined) i += 1;
        break;
      case 'include-informational':
        options.includeInformational = true;
        break;
      default:
        throw new Error(`Unknown option: --${key}`);
    }
  }

  if (!options.feedFile && !options.apiKey) {
    throw new Error('Provide --api-key <key> or --feed-file <json>');
  }

  return options;
}

function printHelp() {
  console.log(`Usage:
  node build-wordfence-package.mjs --api-key <key> --private-key <pem> --out <json>
  node build-wordfence-package.mjs --feed-file <wordfence.json> --private-key <pem> --out <json>

Options:
  --api-key <key>              Wordfence API key. Can also use WORDFENCE_API_KEY.
  --feed-file <json>           Read a previously downloaded Wordfence feed JSON.
  --feed-type <type>           production | scanner. Default: production
  --base-template <json>       Base rules template merged into the final total package.
  --private-key <pem>          Official private key used to sign the package.
  --out <file>                 Output package file path.
  --version <value>            Package version. Default: current UTC date-based version.
  --label <text>               Package label.
  --min-plugin-version <ver>   Override required qilingsecurity plugin version.
  --signer <id>                Signer id. Default: qiling-official-v1
  --component-types <list>     Comma list: plugin,theme. Default: plugin,theme
  --max-items <n>              Max converted entries. Default: 5000
  --timeout-ms <n>             Fetch timeout in milliseconds. Default: 30000
  --include-informational      Keep informational records.
  --help                       Show this help.
`);
}

function normalizeFeedType(value) {
  const normalized = String(value || 'production').trim().toLowerCase();

  if (normalized !== 'production' && normalized !== 'scanner') {
    throw new Error(`Unsupported --feed-type value: ${value}`);
  }

  return normalized;
}

function normalizeComponentTypes(value) {
  const items = String(value || '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  const normalized = new Set(items.length ? items : ['plugin', 'theme']);

  for (const item of normalized) {
    if (item !== 'plugin' && item !== 'theme') {
      throw new Error(`Unsupported component type: ${item}`);
    }
  }

  return normalized;
}

function resolvePath(value) {
  if (!value) {
    return '';
  }

  return path.resolve(process.cwd(), String(value));
}

function readJsonFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(content);
  const root = normalizeFeedRoot(parsed);

  if (!root || typeof root !== 'object' || Array.isArray(root)) {
    throw new Error('Feed JSON root must be an object');
  }

  return root;
}

function loadBaseRules(filePath) {
  if (!filePath) {
    return {};
  }

  if (!fs.existsSync(filePath)) {
    throw new Error(`Base template not found: ${filePath}`);
  }

  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const rules = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed.rules : null;

  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) {
    throw new Error(`Base template is missing a valid rules object: ${filePath}`);
  }

  return { ...rules };
}

async function fetchWordfenceFeed(feedType, apiKey, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${DEFAULT_ENDPOINT_BASE}/${feedType}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/json',
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Wordfence API request failed: ${response.status} ${response.statusText}${body ? ` - ${body.slice(0, 200)}` : ''}`);
    }

    const parsed = normalizeFeedRoot(await response.json());

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Wordfence API returned an unexpected JSON shape');
    }

    return parsed;
  } finally {
    clearTimeout(timer);
  }
}

function buildComponentFeed(feed, options) {
  const entries = [];
  const seen = new Set();

  for (const vulnerability of Object.values(feed)) {
    if (!vulnerability || typeof vulnerability !== 'object') {
      continue;
    }

    if (!options.includeInformational && vulnerability.informational) {
      continue;
    }

    const softwareList = Array.isArray(vulnerability.software) ? vulnerability.software : [];

    for (const software of softwareList) {
      if (!software || typeof software !== 'object') {
        continue;
      }

      const componentType = String(software.type || '').trim().toLowerCase();
      if (!options.componentTypes.has(componentType)) {
        continue;
      }

      const slug = sanitizeSlug(software.slug);
      const title = sanitizeText(vulnerability.title, 180);
      const affectedVersions = buildAffectedVersionExpression(software.affected_versions);

      if (!slug || !title || !affectedVersions) {
        continue;
      }

      const id = sanitizeText(`${String(vulnerability.id || '')}:${componentType}:${slug}`, 120);
      const entry = {
        id,
        component_type: componentType,
        slug,
        title,
        severity: mapSeverity(vulnerability),
        affected_versions: affectedVersions,
        fixed_in: pickFixedVersion(software.patched_versions),
        reference: pickReference(vulnerability),
        source: `wordfence-${options.feedType}`,
        cve: sanitizeText(vulnerability.cve || '', 80),
      };

      const dedupeKey = JSON.stringify(entry);
      if (seen.has(dedupeKey)) {
        continue;
      }

      seen.add(dedupeKey);
      entries.push(entry);

      if (entries.length >= options.maxItems) {
        return entries;
      }
    }
  }

  return entries;
}

function sanitizeSlug(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '');
}

function sanitizeText(value, maxLength) {
  const normalized = String(value || '')
    .replace(/[\0\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  return normalized.length <= maxLength ? normalized : normalized.slice(0, maxLength);
}

function pickFixedVersion(patchedVersions) {
  if (!Array.isArray(patchedVersions) || patchedVersions.length === 0) {
    return '';
  }

  return sanitizeText(String(patchedVersions[0] || ''), 40).replace(/[^a-zA-Z0-9._-]/g, '');
}

function pickReference(vulnerability) {
  const references = Array.isArray(vulnerability.references) ? vulnerability.references : [];
  const preferred = references.find((item) => String(item || '').includes('wordfence.com')) || references[0] || vulnerability.cve_link || '';

  return sanitizeText(String(preferred || ''), 500);
}

function mapSeverity(vulnerability) {
  const rating = String(vulnerability?.cvss?.rating || '').trim().toLowerCase();

  if (rating === 'critical' || rating === 'high') {
    return 'critical';
  }

  if (rating === 'medium' || rating === 'moderate') {
    return 'warning';
  }

  if (rating === 'low' || vulnerability?.informational) {
    return 'info';
  }

  return 'warning';
}

function buildAffectedVersionExpression(affectedVersions) {
  if (!affectedVersions || typeof affectedVersions !== 'object' || Array.isArray(affectedVersions)) {
    return '';
  }

  const groups = [];

  for (const range of Object.values(affectedVersions)) {
    if (!range || typeof range !== 'object') {
      continue;
    }

    const fromVersion = String(range.from_version || '').trim();
    const toVersion = String(range.to_version || '').trim();
    const clauses = [];

    if (fromVersion && fromVersion !== '*') {
      clauses.push(`${range.from_inclusive === false ? '>' : '>='}${fromVersion}`);
    }

    if (toVersion && toVersion !== '*') {
      clauses.push(`${range.to_inclusive === false ? '<' : '<='}${toVersion}`);
    }

    groups.push(clauses.length ? clauses.join(',') : '*');
  }

  return groups.filter(Boolean).join(' || ');
}

function sha256(value) {
  const json = JSON.stringify(value);
  return crypto.createHash('sha256').update(json).digest('hex');
}

function sanitizeRulesForPlugin(rules) {
  const input = rules && typeof rules === 'object' ? rules : {};
  const cleaned = {};

  for (const [ruleKey, defaultValue] of Object.entries(BUILTIN_RULE_DEFAULTS)) {
    if (!(ruleKey in input)) {
      continue;
    }

    let candidate = input[ruleKey];

    if (Array.isArray(defaultValue)) {
      candidate = sanitizeRuleList(ruleKey, candidate);
    } else if (defaultValue && typeof defaultValue === 'object') {
      candidate = sanitizeRuleMap(ruleKey, candidate);
    } else if (typeof defaultValue === 'string') {
      candidate = sanitizeRuleScalar(ruleKey, candidate);
    } else {
      continue;
    }

    if (candidate == null) {
      continue;
    }

    if (Array.isArray(candidate) && candidate.length === 0) {
      continue;
    }

    if (!Array.isArray(candidate) && typeof candidate === 'object' && Object.keys(candidate).length === 0) {
      continue;
    }

    cleaned[ruleKey] = candidate;
  }

  return cleaned;
}

function sanitizeRuleMap(ruleKey, value) {
  if (!value || Array.isArray(value) || typeof value !== 'object') {
    return null;
  }

  const cleaned = {};

  for (const [mapKey, mapValue] of Object.entries(value)) {
    if (ruleKey === 'code_vulnerability_patterns') {
      const key = String(mapKey || '')
        .replace(/[^a-zA-Z0-9_-]/g, '')
        .toUpperCase();
      const val = String(mapValue || '').trim();

      if (!key || !val) {
        continue;
      }

      cleaned[key] = truncateText(val, 500);
      continue;
    }

    if (ruleKey === 'scan_api_endpoints') {
      const routePath = `/${sanitizePlainText(mapKey).replace(/^\/+/, '')}`.replace(/\/+/g, '/');
      const label = sanitizePlainText(mapValue);

      if (!routePath.replace(/^\/+|\/+$/g, '') || !label) {
        continue;
      }

      cleaned[truncateText(routePath, 180)] = truncateText(label, 180);
      continue;
    }

    const key = truncateText(sanitizePlainText(mapKey), 120);
    const val = truncateText(sanitizePlainText(mapValue), 500);

    if (!key || !val) {
      continue;
    }

    cleaned[key] = val;
  }

  return cleaned;
}

function sanitizeRuleList(ruleKey, value) {
  if (!Array.isArray(value)) {
    return null;
  }

  if (ruleKey === 'component_vulnerability_feed') {
    return sanitizeComponentVulnerabilityFeed(value);
  }

  const cleaned = [];

  for (let item of value) {
    item = sanitizePlainText(item);

    if (!item) {
      continue;
    }

    if (ruleKey === 'upload_image_extensions') {
      item = item.toLowerCase().replace(/^\./, '');
    }

    cleaned.push(truncateText(item, 240));
  }

  return [...new Set(cleaned.filter(Boolean))].slice(0, 400);
}

function sanitizeComponentVulnerabilityFeed(value) {
  const cleaned = [];

  for (const item of value) {
    if (!item || Array.isArray(item) || typeof item !== 'object') {
      continue;
    }

    const componentType = String(item.component_type || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, '');
    const slug = String(item.slug || '')
      .toLowerCase()
      .replace(/[^a-z0-9._-]/g, '');
    const title = truncateText(sanitizePlainText(item.title || ''), 180);
    const affected = truncateText(sanitizePlainText(item.affected_versions || ''), 120);

    if (!['plugin', 'theme'].includes(componentType) || !slug || !title || !affected) {
      continue;
    }

    cleaned.push({
      id: truncateText(
        sanitizePlainText(item.id || `${componentType.toUpperCase()}:${slug.toUpperCase()}:${title}`),
        120
      ),
      component_type: componentType,
      slug,
      title,
      severity: sanitizeIssueSeverity(item.severity || 'warning'),
      affected_versions: affected,
      fixed_in: sanitizeVersion(item.fixed_in || ''),
      reference: truncateText(sanitizePlainText(item.reference || ''), 500),
      source: truncateText(sanitizePlainText(item.source || ''), 80),
      cve: truncateText(sanitizePlainText(item.cve || ''), 80),
    });
  }

  const deduped = [];
  const seen = new Set();

  for (const item of cleaned) {
    const key = JSON.stringify(item);
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(item);
  }

  return deduped.slice(0, 5000);
}

function sanitizeRuleScalar(ruleKey, value) {
  value = String(value || '').trim();

  if (!value) {
    return null;
  }

  return truncateText(sanitizePlainText(value), 500);
}

function sanitizePlainText(value) {
  return String(value || '')
    .replace(/\0|\r|\n|\t/g, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
}

function sanitizeVersion(value) {
  return truncateText(sanitizePlainText(value).replace(/[^a-zA-Z0-9._-]/g, ''), 40);
}

function sanitizeIssueSeverity(value) {
  const normalized = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '');

  if (['critical', 'warning', 'info'].includes(normalized)) {
    return normalized;
  }

  if (normalized === 'high') {
    return 'critical';
  }

  if (normalized === 'medium' || normalized === 'moderate') {
    return 'warning';
  }

  if (normalized === 'low') {
    return 'info';
  }

  return 'warning';
}

function truncateText(value, maxLength) {
  return Array.from(String(value || '')).slice(0, Math.max(1, maxLength)).join('');
}

function normalizeForHash(value) {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeForHash(item));
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  const normalized = {};
  for (const key of Object.keys(value).sort()) {
    normalized[key] = normalizeForHash(value[key]);
  }
  return normalized;
}

function signPayload(payload, privateKey) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(JSON.stringify(payload));
  signer.end();
  return signer.sign(privateKey, 'base64');
}

function buildDefaultVersion() {
  const isoDate = new Date().toISOString().slice(0, 10).replace(/-/g, '.');
  return `${isoDate}-wf`;
}

function detectPluginVersion() {
  const pluginFile = path.resolve(SCRIPT_DIR, '../qilingsecurity.php');

  if (!fs.existsSync(pluginFile)) {
    return '1.16.0';
  }

  const content = fs.readFileSync(pluginFile, 'utf8');
  const match = content.match(/^\s*\*\s*Version:\s*([^\r\n]+)$/m);

  if (!match) {
    return '1.16.0';
  }

  return sanitizeText(match[1], 40).replace(/[^a-zA-Z0-9._-]/g, '') || '1.16.0';
}

function normalizeFeedRoot(payload) {
  if (payload && typeof payload === 'object' && !Array.isArray(payload) && payload.data && typeof payload.data === 'object' && !Array.isArray(payload.data)) {
    return payload.data;
  }

  return payload;
}
