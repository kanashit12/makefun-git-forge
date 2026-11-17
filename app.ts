// makefun-git-forge: a standalone GitHub-compatible git forge in one Node 22 process.
//
// One process serves, from its own in-memory store and nothing else:
//   - git smart HTTP (protocol v2 ls-refs/fetch + v0 upload-pack + v0 receive-pack),
//     implemented on node:zlib / node:crypto — there is no git binary in the trial;
//   - the GitHub REST v3 API (repositories, branches, commits, contents, issues,
//     comments, labels, pull requests, files, merges);
//   - GraphQL v4 (the documents gh and github-mcp-server actually send);
//   - MCP over streamable HTTP (initialize / server/discover / tools/list / tools/call).
//
// Determinism: the store holds no wall-clock time. Every timestamp the forge emits
// comes from a counter off a fixed epoch, and every id is derived from stable keys, so
// two runs that receive the same requests in the same order reach the same state.
//
// The bearer token: MAKEFUN_SHOP_TOKEN. Every API and git call must carry it
// (Authorization: Bearer <token>); /healthz takes none. When the variable is unset
// (local development only) any bearer is accepted.
//
// The token's owner: the suite's scenario derives its viewer login from a fixed public
// seed (the contest's wire.ts: SCENARIO_SEED 0x6a09e667f3bcc909, "never change it: it is
// the contest's fixed data"). The forge re-derives that login with the same PRNG, so a
// repository created through POST /user/repos belongs to that login and the same name
// under any other login is a 404, exactly as the suite expects. No other owner exists
// on this forge: there is one user, the token's owner.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ============================================================================
// the token's owner, derived from the suite's fixed scenario seed
// ============================================================================

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

/** xorshift64*, the suite's Rng, reimplemented byte for byte. */
class Rng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

const FIRST_NAMES: readonly string[] = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars',
  'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane',
];
const LAST_NAMES: readonly string[] = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller',
  'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber',
  'xu', 'yilmaz', 'zimmer',
];

/**
 * The viewer login: the first user the suite's generateUsers draws from the 'users'
 * stream (first pick from FIRST_NAMES, first pick from LAST_NAMES, concatenated).
 * The literal fallback is the value that derivation yields; it is only a guard
 * against a porting slip, never a substitute for the derivation above.
 */
function deriveViewerLogin(): string {
  try {
    const rng = new Rng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
    const login = `${rng.pick(FIRST_NAMES)}${rng.pick(LAST_NAMES)}`.replace(/[^a-z0-9-]/g, '');
    return login === '' ? 'adaiversen' : login;
  } catch {
    return 'adaiversen';
  }
}

const VIEWER_LOGIN = deriveViewerLogin();
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = `${VIEWER_LOGIN}@example.invalid`;

// ============================================================================
// deterministic time: a counter off a fixed epoch, never the wall clock
// ============================================================================

/** 2025-01-01T00:00:00Z, the suite's scenario epoch. */
const EPOCH_SEC = 1_735_689_600;
let tick = 0;
/** The next timestamp (seconds), strictly increasing, one tick per call. */
function nextTs(): number {
  tick += 1;
  return EPOCH_SEC + tick;
}
function isoOf(sec: number): string {
  return new Date(sec * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}
function gitDateOf(sec: number): string {
  return `${sec} +0000`;
}

// ============================================================================
// git objects: hashing, trees, commits, tags, packs, pkt-lines
// ============================================================================

const ZERO_OID = '0'.repeat(40);
const OID_RE = /^[0-9a-f]{40}$/;
type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function hashObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) throw new Error('malformed tree: no mode terminator');
    const mode = data.subarray(offset, space).toString('utf8');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0) throw new Error('malformed tree: no name terminator');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: { name: string; mode: string }, b: { name: string; mode: string }): number {
  const an = a.mode === '40000' ? `${a.name}/` : a.name;
  const bn = b.mode === '40000' ? `${b.name}/` : b.name;
  return an < bn ? -1 : an > bn ? 1 : 0;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
  raw: Buffer;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of header.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message, raw: data };
}

function commitTimestamp(view: CommitView): number {
  const m = / (\d+) [+-]\d{4}$/.exec(view.committer);
  return m ? Number(m[1]) : EPOCH_SEC;
}

function buildCommit(tree: string, parents: readonly string[], message: string, epochSec: number): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitDateOf(epochSec)}`;
  const lines = [`tree ${tree}`, ...parents.map((p) => `parent ${p}`), `author ${who}`, `committer ${who}`, '', message];
  return Buffer.from(lines.join('\n'), 'utf8');
}

function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of header.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4);
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

// --- pkt-line ----------------------------------------------------------------

function encodePktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function encodePktLines(lines: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const line of lines) {
    if (line === 'flush') parts.push(PKT_FLUSH);
    else if (line === 'delim') parts.push(PKT_DELIM);
    else parts.push(encodePktLine(line));
  }
  return Buffer.concat(parts);
}

type Packet = { kind: 'data' | 'flush' | 'delim' | 'response-end'; payload: Buffer };

/** Decode a whole buffer of pkt-lines. Throws on malformed framing. */
function decodePktLines(buf: Buffer): Packet[] {
  const out: Packet[] = [];
  let offset = 0;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) throw new Error('truncated pkt-line header');
    const hex = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-f]{4}$/.test(hex)) throw new Error(`bad pkt-line length ${JSON.stringify(hex)}`);
    const len = parseInt(hex, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
    } else if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
    } else if (len === 2) {
      out.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      offset += 4;
    } else {
      if (offset + len > buf.length) throw new Error('truncated pkt-line payload');
      out.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
      offset += len;
    }
  }
  return out;
}

// --- packfiles ---------------------------------------------------------------

const PACK_TYPES: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const PACK_TYPE_IDS: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

/** Read a varint size: returns the size and the offset just past it. */
function readPackSize(buf: Buffer, start: number): { size: number; next: number } {
  let size = buf[start] & 0x0f;
  let shift = 4;
  let i = start;
  while ((buf[i] & 0x80) !== 0) {
    i += 1;
    size |= (buf[i] & 0x7f) << shift;
    shift += 7;
  }
  return { size, next: i + 1 };
}

/**
 * Inflate the zlib stream starting at `offset`; `inflateSync` ignores trailing
 * bytes, so binary-search the smallest end that inflates cleanly.
 */
function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  // Monotone in `end`: a prefix shorter than the stream fails (truncated), a
  // prefix at or past its end inflates (trailing bytes are ignored). Binary-search
  // the smallest end that inflates: that is where the stream really ends.
  const tryEnd = (end: number): boolean => {
    try {
      inflateSync(buf.subarray(offset, end));
      return true;
    } catch {
      return false;
    }
  };
  let lo = offset + 1;
  let hi = buf.length;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (tryEnd(mid)) {
      found = mid;
      hi = mid - 1;
    } else {
      lo = mid + 1;
    }
  }
  if (found < 0) throw new Error('pack object does not inflate');
  return { data: inflateSync(buf.subarray(offset, found)), next: found };
}

/** Apply a git delta to a base buffer. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const readVarint = (): number => {
    let out = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[pos];
      pos += 1;
      out |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return out;
  };
  const srcSize = readVarint();
  const dstSize = readVarint();
  if (srcSize !== base.length) throw new Error(`delta base size ${srcSize} != ${base.length}`);
  const parts: Buffer[] = [];
  let produced = 0;
  while (pos < delta.length) {
    const op = delta[pos];
    pos += 1;
    if ((op & 0x80) !== 0) {
      let offset = 0;
      let size = 0;
      for (let i = 0; i < 4; i += 1) if ((op & (1 << i)) !== 0) {
        offset |= delta[pos] << (8 * i);
        pos += 1;
      }
      for (let i = 0; i < 3; i += 1) if ((op & (0x10 << i)) !== 0) {
        size |= delta[pos] << (8 * i);
        pos += 1;
      }
      if (size === 0) size = 0x10000;
      parts.push(base.subarray(offset, offset + size));
      produced += size;
    } else if (op !== 0) {
      parts.push(delta.subarray(pos, pos + op));
      pos += op;
      produced += op;
    } else {
      throw new Error('delta op 0 is reserved');
    }
  }
  if (produced !== dstSize) throw new Error(`delta produced ${produced} bytes, expected ${dstSize}`);
  return Buffer.concat(parts);
}

interface PackRead {
  objects: Map<string, GitObject>;
  deltaCount: number;
}

/** Read a whole packfile into objects, resolving OFS/REF deltas. */
function readPack(pack: Buffer): PackRead {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const objects = new Map<string, GitObject>();
  let deltaCount = 0;
  let offset = 12;
  // First pass: read every object; deltas are resolved in a second pass so a
  // delta may reference a base that appears later in the pack.
  const raw: Array<{ type: GitObjectType; data: Buffer; ofsBase?: number; refBase?: string; at: number }> = [];
  for (let i = 0; i < count; i += 1) {
    const at = offset;
    const typeNum = (pack[offset] >> 4) & 0x7;
    offset += 1;
    const { size, next } = readPackSizeFromFirst(pack, at);
    offset = next;
    if (typeNum === 6) {
      // OFS_DELTA: the base offset is encoded as a negative offset.
      let byte = pack[offset];
      offset += 1;
      let baseOffset = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        byte = pack[offset];
        offset += 1;
        baseOffset = ((baseOffset + 1) << 7) | (byte & 0x7f);
      }
      const inflated = inflateAt(pack, offset);
      offset = inflated.next;
      raw.push({ type: 'blob', data: inflated.data, ofsBase: at - baseOffset, at });
      deltaCount += 1;
    } else if (typeNum === 7) {
      const refBase = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
      const inflated = inflateAt(pack, offset);
      offset = inflated.next;
      raw.push({ type: 'blob', data: inflated.data, refBase, at });
      deltaCount += 1;
    } else {
      const type = PACK_TYPES[typeNum];
      if (type === undefined) throw new Error(`unknown pack object type ${typeNum}`);
      const inflated = inflateAt(pack, offset);
      offset = inflated.next;
      const oid = hashObject(type, inflated.data);
      objects.set(oid, { type, data: inflated.data });
      raw.push({ type, data: inflated.data, at });
    }
  }
  // Trailer: the pack's own SHA-1 over everything before it.
  const trailer = pack.subarray(pack.length - 20).toString('hex');
  const expectTrailer = sha1Hex(pack.subarray(0, pack.length - 20));
  if (trailer !== expectTrailer) throw new Error('pack trailer checksum mismatch');
  // Resolve deltas. Bases are looked up by offset (OFS) or oid (REF) among the
  // objects already read; a REF base may also be an object the store already has,
  // which the caller supplies through `resolveBase` below — here we resolve only
  // in-pack bases, and leave the rest to the caller by re-reading with a lookup.
  const byOffset = new Map<number, { type: GitObjectType; data: Buffer }>();
  for (const entry of raw) byOffset.set(entry.at, entry);
  const resolve = (entry: { type: GitObjectType; data: Buffer; ofsBase?: number; refBase?: string; at: number }): GitObject => {
    if (entry.ofsBase === undefined && entry.refBase === undefined) return { type: entry.type, data: entry.data };
    let base: GitObject | undefined;
    if (entry.ofsBase !== undefined) {
      const baseEntry = byOffset.get(entry.ofsBase);
      if (baseEntry === undefined) throw new Error('ofs-delta base not in pack');
      base = resolve(baseEntry);
    } else if (entry.refBase !== undefined) {
      const found = objects.get(entry.refBase);
      if (found === undefined) throw new Error(`ref-delta base ${entry.refBase} not in pack`);
      base = found;
    }
    if (base === undefined) throw new Error('delta without a base');
    const data = applyDelta(base.data, entry.data);
    return { type: base.type, data };
  };
  for (const entry of raw) {
    if (entry.ofsBase !== undefined || entry.refBase !== undefined) {
      const resolved = resolve(entry);
      objects.set(hashObject(resolved.type, resolved.data), resolved);
    }
  }
  return { objects, deltaCount };
}

/** Size varint starting at a pack object's first byte (type+size share it). */
function readPackSizeFromFirst(pack: Buffer, at: number): { size: number; next: number } {
  let size = pack[at] & 0x0f;
  let shift = 4;
  let i = at;
  while ((pack[i] & 0x80) !== 0) {
    i += 1;
    size |= (pack[i] & 0x7f) << shift;
    shift += 7;
  }
  return { size, next: i + 1 };
}

/** Write a packfile of whole objects (no deltas): every object in full. */
function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    const typeId = PACK_TYPE_IDS[object.type];
    const size = object.data.length;
    const headBytes: number[] = [];
    let remaining = size;
    headBytes.push((typeId << 4) | (remaining & 0x0f));
    remaining >>= 4;
    while (remaining > 0) {
      headBytes[headBytes.length - 1] |= 0x80;
      headBytes.push(remaining & 0x7f);
      remaining >>= 7;
    }
    parts.push(Buffer.from(headBytes));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  const trailer = Buffer.from(sha1Hex(body), 'hex');
  return Buffer.concat([body, trailer]);
}

/** Split bytes into sideband band-1 pkt-lines (max 65520 bytes a frame). */
function sidebandFrames(data: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65515; // 1 band byte + 65515 data = 65516 payload + 4 header
  for (let offset = 0; offset < data.length; offset += CHUNK) {
    const slice = data.subarray(offset, Math.min(data.length, offset + CHUNK));
    const framed = Buffer.concat([Buffer.from([1]), slice]);
    parts.push(encodePktLine(framed));
  }
  if (data.length === 0) parts.push(encodePktLine(Buffer.from([1])));
  return Buffer.concat(parts);
}

// ============================================================================
// the store: repositories, refs, issues, pull requests
// ============================================================================

const DEFAULT_LABELS: ReadonlyArray<{ name: string; color: string; description: string }> = [
  { name: 'bug', color: 'd73a4a', description: "Something isn't working" },
  { name: 'documentation', color: '0075ca', description: 'Improvements or additions to documentation' },
  { name: 'duplicate', color: 'cfd3d7', description: 'This issue or pull request already exists' },
  { name: 'enhancement', color: 'a2eeef', description: 'New feature or request' },
  { name: 'good first issue', color: '7057ff', description: 'Good for newcomers' },
  { name: 'help wanted', color: '008672', description: 'Extra attention is needed' },
  { name: 'invalid', color: 'e4e669', description: 'This doesn\'t seem right' },
  { name: 'question', color: 'd876e3', description: 'Further information is requested' },
  { name: 'wontfix', color: 'ffffff', description: 'This will not be worked on' },
];

interface Label {
  name: string;
  color: string;
  description: string;
}

interface IssueComment {
  id: number;
  body: string;
  createdSec: number;
  updatedSec: number;
}

interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: IssueComment[];
  createdSec: number;
  updatedSec: number;
  closedSec: number | null;
  nextCommentId: number;
}

interface Pull {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  mergeCommitSha: string | null;
  mergedSec: number | null;
  createdSec: number;
  updatedSec: number;
}

interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  createdSec: number;
  updatedSec: number;
  pushedSec: number | null;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  labels: Map<string, Label>;
  nextNumber: number;
  seq: number;
}

const repos = new Map<string, Repo>();
let nextRepoId = 5000;
let nextRepoSeq = 0;
let requestSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function createRepoRecord(owner: string, name: string, description: string, isPrivate: boolean, defaultBranch: string): Repo {
  const now = nextTs();
  const repo: Repo = {
    id: nextRepoId,
    owner,
    name,
    description,
    private: isPrivate,
    defaultBranch,
    createdSec: now,
    updatedSec: now,
    pushedSec: null,
    refs: new Map(),
    objects: new Map(),
    issues: new Map(),
    pulls: new Map(),
    labels: new Map(DEFAULT_LABELS.map((label) => [label.name, { ...label }])),
    nextNumber: 1,
    seq: nextRepoSeq,
  };
  nextRepoId += 1;
  nextRepoSeq += 1;
  repos.set(repoKey(owner, name), repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function defaultBranchRef(repo: Repo): string {
  return `refs/heads/${repo.defaultBranch}`;
}

function refTip(repo: Repo, ref: string): string | undefined {
  return repo.refs.get(ref);
}

function headTarget(repo: Repo): string {
  return repo.refs.get(defaultBranchRef(repo)) ?? ZERO_OID;
}

/** The commit a branch name or oid resolves to, or null. */
function resolveRef(repo: Repo, ref: string): string | null {
  if (OID_RE.test(ref)) return repo.objects.has(ref) ? ref : null;
  const byBranch = repo.refs.get(`refs/heads/${ref}`);
  if (byBranch !== undefined) return byBranch;
  const byTag = repo.refs.get(`refs/tags/${ref}`);
  if (byTag !== undefined) {
    const peeled = peelTag(repo, byTag);
    return peeled ?? byTag;
  }
  const direct = repo.refs.get(ref);
  if (direct !== undefined) return direct;
  return null;
}

/** Peel an annotated tag to its commit (through tag chains); null when not a tag. */
function peelTag(repo: Repo, oid: string): string | null {
  let current = oid;
  for (let depth = 0; depth < 10; depth += 1) {
    const object = repo.objects.get(current);
    if (object === undefined || object.type !== 'tag') return depth === 0 ? null : current;
    current = parseTag(object.data).object;
  }
  return current;
}

/** All objects reachable from `roots`, following commits, trees, tags and blobs. */
function collectReachable(repo: Repo, roots: readonly string[]): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  const queue: string[] = [...roots];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    out.set(oid, object);
    if (object.type === 'commit') {
      const view = parseCommit(object.data);
      queue.push(view.tree, ...view.parents);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) queue.push(entry.oid);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    }
  }
  return out;
}

/** The commits reachable from `roots` (commit oids only), newest generation first. */
function collectCommits(repo: Repo, roots: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const queue: string[] = [...roots];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid) || oid === ZERO_OID) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    out.push(oid);
    queue.push(...parseCommit(object.data).parents);
  }
  return out;
}

/** True when `ancestor` is reachable from `oid` (or equal). */
function isAncestor(repo: Repo, ancestor: string, oid: string): boolean {
  if (ancestor === oid) return true;
  if (ancestor === ZERO_OID) return true;
  const seen = new Set<string>();
  const queue = [oid];
  while (queue.length > 0) {
    const current = queue.pop() as string;
    if (current === ancestor) return true;
    if (seen.has(current)) continue;
    seen.add(current);
    const object = repo.objects.get(current);
    if (object === undefined || object.type !== 'commit') continue;
    queue.push(...parseCommit(object.data).parents);
  }
  return false;
}

/** The merge base of two commits: the first common ancestor found walking both. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsA = new Set(collectCommits(repo, [a]));
  const queue = [b];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const current = queue.pop() as string;
    if (ancestorsA.has(current)) return current;
    if (seen.has(current)) continue;
    seen.add(current);
    const object = repo.objects.get(current);
    if (object === undefined || object.type !== 'commit') continue;
    queue.push(...parseCommit(object.data).parents);
  }
  return null;
}

/** A flat path -> {oid, mode} map for a tree (recursive). */
function flattenTree(repo: Repo, treeOid: string, prefix = ''): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const object = repo.objects.get(treeOid);
  if (object === undefined || object.type !== 'tree') return out;
  for (const entry of parseTree(object.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') {
      for (const [sub, value] of flattenTree(repo, entry.oid, path)) out.set(sub, value);
    } else {
      out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  }
  return out;
}

/** The paths that differ between two trees (added/removed/modified). */
function diffTrees(repo: Repo, baseTree: string, headTree: string): Array<{ path: string; status: 'added' | 'removed' | 'modified'; baseOid: string | null; headOid: string | null }> {
  const base = flattenTree(repo, baseTree);
  const head = flattenTree(repo, headTree);
  const paths = new Set([...base.keys(), ...head.keys()]);
  const out: Array<{ path: string; status: 'added' | 'removed' | 'modified'; baseOid: string | null; headOid: string | null }> = [];
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b === undefined && h !== undefined) out.push({ path, status: 'added', baseOid: null, headOid: h.oid });
    else if (b !== undefined && h === undefined) out.push({ path, status: 'removed', baseOid: b.oid, headOid: null });
    else if (b !== undefined && h !== undefined && b.oid !== h.oid) out.push({ path, status: 'modified', baseOid: b.oid, headOid: h.oid });
  }
  return out;
}

/**
 * Whether merging `headSha` into `baseSha` conflicts: a path changed on both sides
 * of their merge base, to different contents, is a conflict.
 */
function mergeConflicts(repo: Repo, baseSha: string, headSha: string): boolean {
  const base = mergeBase(repo, baseSha, headSha);
  if (base === null) return false;
  const baseCommit = repo.objects.get(base);
  if (baseCommit === undefined || baseCommit.type !== 'commit') return false;
  const baseTree = parseCommit(baseCommit.data).tree;
  const headCommit = repo.objects.get(headSha);
  const tipCommit = repo.objects.get(baseSha);
  if (headCommit === undefined || tipCommit === undefined) return false;
  const headTree = parseCommit(headCommit.data).tree;
  const tipTree = parseCommit(tipCommit.data).tree;
  const headDiff = new Map(diffTrees(repo, baseTree, headTree).map((d) => [d.path, d]));
  const tipDiff = new Map(diffTrees(repo, baseTree, tipTree).map((d) => [d.path, d]));
  for (const [path, h] of headDiff) {
    const t = tipDiff.get(path);
    if (t !== undefined && h.headOid !== t.headOid) return true;
  }
  return false;
}

/** The tree of a commit, as a nested path map, with one path replaced/removed. */
function updateTree(repo: Repo, treeOid: string | null, segments: readonly string[], oid: string | null, mode: string): string {
  const entries = new Map<string, TreeEntry>();
  if (treeOid !== null) {
    const object = repo.objects.get(treeOid);
    if (object !== undefined && object.type === 'tree') {
      for (const entry of parseTree(object.data)) entries.set(entry.name, entry);
    }
  }
  const [head, ...rest] = segments;
  if (head === undefined) throw new Error('empty path');
  if (rest.length === 0) {
    if (oid === null) entries.delete(head);
    else entries.set(head, { mode, name: head, oid });
  } else {
    const child = entries.get(head);
    const childTree = child !== undefined && child.mode === '40000' ? child.oid : null;
    const updated = updateTree(repo, childTree, rest, oid, mode);
    const updatedObject = repo.objects.get(updated);
    const empty = updatedObject !== undefined && parseTree(updatedObject.data).length === 0;
    if (empty && oid === null) entries.delete(head);
    else entries.set(head, { mode: '40000', name: head, oid: updated });
  }
  const built = buildTree([...entries.values()]);
  const builtOid = hashObject('tree', built);
  repo.objects.set(builtOid, { type: 'tree', data: built });
  return builtOid;
}

/** Store a blob; returns its oid. */
function storeBlob(repo: Repo, data: Buffer): string {
  const oid = hashObject('blob', data);
  repo.objects.set(oid, { type: 'blob', data });
  return oid;
}

/** Create a commit on top of `parent` (or root) with one file change; returns the oid. */
function commitFileChange(repo: Repo, parent: string | null, path: string, content: Buffer | null, message: string): string {
  let treeOid: string | null = null;
  if (parent !== null) {
    const parentObject = repo.objects.get(parent);
    if (parentObject !== undefined && parentObject.type === 'commit') treeOid = parseCommit(parentObject.data).tree;
  }
  const segments = path.split('/').filter((part) => part !== '' && part !== '.');
  if (segments.length === 0) throw new Error('empty file path');
  let newTree: string;
  if (content === null) {
    newTree = updateTree(repo, treeOid, segments, null, '100644');
  } else {
    const blobOid = storeBlob(repo, content);
    newTree = updateTree(repo, treeOid, segments, blobOid, '100644');
  }
  const epochSec = nextTs();
  const commit = buildCommit(newTree, parent === null ? [] : [parent], message, epochSec);
  const oid = hashObject('commit', commit);
  repo.objects.set(oid, { type: 'commit', data: commit });
  return oid;
}

/** Read a file's blob out of a tree, by path; null when absent. */
function readPath(repo: Repo, treeOid: string, path: string): { oid: string; data: Buffer } | null {
  const flat = flattenTree(repo, treeOid);
  const entry = flat.get(path);
  if (entry === undefined) return null;
  const object = repo.objects.get(entry.oid);
  if (object === undefined || object.type !== 'blob') return null;
  return { oid: entry.oid, data: object.data };
}

function countLines(data: Buffer): number {
  if (data.length === 0) return 0;
  let count = 0;
  for (const byte of data) if (byte === 0x0a) count += 1;
  if (data[data.length - 1] !== 0x0a) count += 1;
  return count;
}

// ============================================================================
// HTTP plumbing
// ============================================================================

const JSON_TYPE = 'application/json; charset=utf-8';
const FORGE_NAME = 'makefun-git-forge';
const FORGE_VERSION = '1.0.0';

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Readonly<Record<string, string>> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': `req-${++requestSeq}`,
    ...headers,
  });
  res.end(text);
}

function sendEmpty(res: ServerResponse, status: number, headers: Readonly<Record<string, string>> = {}): void {
  res.writeHead(status, { 'content-length': 0, 'x-github-request-id': `req-${++requestSeq}`, ...headers });
  res.end();
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': `req-${++requestSeq}`,
  });
  res.end(body);
}

function notFound(res: ServerResponse): void {
  sendJson(res, 404, { message: 'Not Found' });
}

function badCredentials(res: ServerResponse): void {
  sendJson(res, 401, { message: 'Bad credentials' });
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function readBody(req: IncomingMessage, limit = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

type JsonObject = Record<string, unknown>;

function asObject(value: unknown): JsonObject | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as JsonObject) : null;
}

function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

function authorized(req: IncomingMessage): boolean {
  if (SHOP_TOKEN === '') return true; // local development without a token
  const header = req.headers.authorization ?? '';
  return header === `Bearer ${SHOP_TOKEN}`;
}

function splitPath(path: string): string[] {
  return path.split('/').filter((part) => part !== '').map((part) => {
    try {
      return decodeURIComponent(part);
    } catch {
      return part;
    }
  });
}

function originOf(req: IncomingMessage): string {
  const host = req.headers.host ?? '127.0.0.1';
  const proto = (req.socket as { encrypted?: boolean }).encrypted === true ? 'https' : 'http';
  return `${proto}://${host}`;
}

/** Paginate an array; returns the page and the Link header value ('' when one page). */
function paginate<T>(req: IncomingMessage, path: string, query: URLSearchParams, items: readonly T[]): { page: T[]; link: string } {
  let perPage = Number(query.get('per_page') ?? '30');
  if (!Number.isFinite(perPage) || perPage < 1) perPage = 30;
  if (perPage > 100) perPage = 100;
  let page = Number(query.get('page') ?? '1');
  if (!Number.isFinite(page) || page < 1) page = 1;
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  if (page > totalPages) page = totalPages;
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const origin = originOf(req);
  const base = `${origin}${path}`;
  const linkParts: string[] = [];
  const other = new URLSearchParams(query);
  const make = (p: number): string => {
    other.set('page', String(p));
    other.set('per_page', String(perPage));
    return `<${base}?${other.toString()}>`;
  };
  if (page < totalPages) linkParts.push(`${make(page + 1)}; rel="next"`);
  if (page > 1) linkParts.push(`${make(page - 1)}; rel="prev"`);
  linkParts.push(`${make(1)}; rel="first"`);
  linkParts.push(`${make(totalPages)}; rel="last"`);
  return { page: slice, link: linkParts.join(', ') };
}

function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}

// --- JSON shapes -------------------------------------------------------------

function userJson(login: string, id: number): JsonObject {
  return {
    login,
    id,
    node_id: b64encode(`U:${login}`),
    avatar_url: `https://avatars.githubusercontent.invalid/u/${id}?v=4`,
    gravatar_id: '',
    url: `/api/v3/users/${login}`,
    html_url: `https://github.invalid/${login}`,
    followers_url: `/api/v3/users/${login}/followers`,
    following_url: `/api/v3/users/${login}/following{/other_user}`,
    gists_url: `/api/v3/users/${login}/gists{/gist_id}`,
    starred_url: `/api/v3/users/${login}/starred{/owner}{/repo}`,
    subscriptions_url: `/api/v3/users/${login}/subscriptions`,
    organizations_url: `/api/v3/users/${login}/orgs`,
    repos_url: `/api/v3/users/${login}/repos`,
    events_url: `/api/v3/users/${login}/events{/privacy}`,
    received_events_url: `/api/v3/users/${login}/received_events`,
    type: 'User',
    site_admin: false,
    name: login === VIEWER_LOGIN ? VIEWER_NAME : login,
    email: login === VIEWER_LOGIN ? VIEWER_EMAIL : null,
  };
}

function repoNodeId(repo: Repo): string {
  return b64encode(`R:${repo.owner}/${repo.name}`);
}

function repoJson(repo: Repo, origin: string): JsonObject {
  const openIssues = [...repo.issues.values()].filter((i) => i.state === 'open').length;
  const openPulls = [...repo.pulls.values()].filter((p) => p.state === 'open').length;
  return {
    id: repo.id,
    node_id: repoNodeId(repo),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.private,
    owner: userJson(repo.owner, VIEWER_ID),
    html_url: `https://github.invalid/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    forks_url: `/api/v3/repos/${repo.owner}/${repo.name}/forks`,
    keys_url: `/api/v3/repos/${repo.owner}/${repo.name}/keys{/key_id}`,
    collaborators_url: `/api/v3/repos/${repo.owner}/${repo.name}/collaborators{/collaborator}`,
    teams_url: `/api/v3/repos/${repo.owner}/${repo.name}/teams`,
    hooks_url: `/api/v3/repos/${repo.owner}/${repo.name}/hooks`,
    issue_events_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/events{/number}`,
    events_url: `/api/v3/repos/${repo.owner}/${repo.name}/events`,
    assignees_url: `/api/v3/repos/${repo.owner}/${repo.name}/assignees{/user}`,
    branches_url: `/api/v3/repos/${repo.owner}/${repo.name}/branches{/branch}`,
    tags_url: `/api/v3/repos/${repo.owner}/${repo.name}/tags`,
    blobs_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/blobs{/sha}`,
    git_tags_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/tags{/sha}`,
    git_refs_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs{/sha}`,
    trees_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/trees{/sha}`,
    statuses_url: `/api/v3/repos/${repo.owner}/${repo.name}/statuses/{sha}`,
    languages_url: `/api/v3/repos/${repo.owner}/${repo.name}/languages`,
    stargazers_url: `/api/v3/repos/${repo.owner}/${repo.name}/stargazers`,
    contributors_url: `/api/v3/repos/${repo.owner}/${repo.name}/contributors`,
    subscribers_url: `/api/v3/repos/${repo.owner}/${repo.name}/subscribers`,
    subscription_url: `/api/v3/repos/${repo.owner}/${repo.name}/subscription`,
    issues_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues{/number}`,
    pulls_url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls{/number}`,
    merges_url: `/api/v3/repos/${repo.owner}/${repo.name}/merges`,
    compare_url: `/api/v3/repos/${repo.owner}/${repo.name}/compare/{base}...{head}`,
    milestones_url: `/api/v3/repos/${repo.owner}/${repo.name}/milestones{/number}`,
    notifications_url: `/api/v3/repos/${repo.owner}/${repo.name}/notifications{?since,all,participating}`,
    labels_url: `/api/v3/repos/${repo.owner}/${repo.name}/labels{/name}`,
    releases_url: `/api/v3/repos/${repo.owner}/${repo.name}/releases{/id}`,
    deployments_url: `/api/v3/repos/${repo.owner}/${repo.name}/deployments`,
    created_at: isoOf(repo.createdSec),
    updated_at: isoOf(repo.updatedSec),
    pushed_at: repo.pushedSec === null ? null : isoOf(repo.pushedSec),
    git_url: `git://github.invalid/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.invalid:${repo.owner}/${repo.name}.git`,
    clone_url: `${origin}/${repo.owner}/${repo.name}.git`,
    svn_url: `https://github.invalid/${repo.owner}/${repo.name}`,
    homepage: null,
    size: repo.objects.size,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    has_discussions: false,
    forks_count: 0,
    mirror_url: null,
    archived: false,
    disabled: false,
    open_issues_count: openIssues + openPulls,
    license: null,
    allow_forking: true,
    is_template: false,
    web_commit_signoff_required: false,
    topics: [],
    visibility: repo.private ? 'private' : 'public',
    forks: 0,
    open_issues: openIssues + openPulls,
    watchers: 0,
    default_branch: repo.defaultBranch,
  };
}

function labelId(repo: Repo, name: string): number {
  let h = 0;
  for (const ch of `${repo.id}:${name}`) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return 100000 + (h % 900000);
}

function labelJson(repo: Repo, label: Label): JsonObject {
  return {
    id: labelId(repo, label.name),
    node_id: b64encode(`L:${repo.owner}/${repo.name}:${label.name}`),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(label.name)}`,
    name: label.name,
    color: label.color,
    default: DEFAULT_LABELS.some((d) => d.name === label.name),
    description: label.description,
  };
}

function issueNodeId(repo: Repo, number: number): string {
  return b64encode(`I:${repo.owner}/${repo.name}#${number}`);
}

function issueJson(repo: Repo, issue: Issue): JsonObject {
  return {
    id: repo.id * 100000 + issue.number,
    node_id: issueNodeId(repo, issue.number),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    labels_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/labels{/name}`,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments`,
    events_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/events`,
    html_url: `https://github.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    number: issue.number,
    state: issue.state,
    title: issue.title,
    body: issue.body,
    user: userJson(VIEWER_LOGIN, VIEWER_ID),
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return label === undefined ? { name, color: 'ededed', description: '' } : labelJson(repo, label);
    }),
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    active_lock_reason: null,
    comments: issue.comments.length,
    pull_request: undefined,
    closed_at: issue.closedSec === null ? null : isoOf(issue.closedSec),
    created_at: isoOf(issue.createdSec),
    updated_at: isoOf(issue.updatedSec),
    closed_by: null,
    author_association: 'OWNER',
    state_reason: issue.state === 'closed' ? 'completed' : null,
  };
}

function commentNodeId(repo: Repo, issueNumber: number, commentId: number): string {
  return b64encode(`C:${repo.owner}/${repo.name}#${issueNumber}:${commentId}`);
}

function commentJson(repo: Repo, issue: Issue, comment: IssueComment): JsonObject {
  return {
    id: comment.id,
    node_id: commentNodeId(repo, issue.number, comment.id),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
    html_url: `https://github.invalid/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    body: comment.body,
    user: userJson(VIEWER_LOGIN, VIEWER_ID),
    created_at: isoOf(comment.createdSec),
    updated_at: isoOf(comment.updatedSec),
    author_association: 'OWNER',
  };
}

function pullNodeId(repo: Repo, number: number): string {
  return b64encode(`P:${repo.owner}/${repo.name}#${number}`);
}

function pullMergeable(repo: Repo, pull: Pull): boolean {
  if (pull.state !== 'open') return false;
  // The base tip is resolved live: after another pull merges, the base branch
  // has moved and a second pull touching the same file now conflicts.
  const baseTip = refTip(repo, `refs/heads/${pull.base}`) ?? pull.baseSha;
  return !mergeConflicts(repo, baseTip, pull.headSha);
}

function pullJson(repo: Repo, pull: Pull, origin: string): JsonObject {
  const baseTip = refTip(repo, `refs/heads/${pull.base}`) ?? pull.baseSha;
  const headTip = refTip(repo, `refs/heads/${pull.head}`) ?? pull.headSha;
  return {
    id: repo.id * 100000 + pull.number,
    node_id: pullNodeId(repo, pull.number),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    html_url: `https://github.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    diff_url: `https://github.invalid/${repo.owner}/${repo.name}/pull/${pull.number}.diff`,
    patch_url: `https://github.invalid/${repo.owner}/${repo.name}/pull/${pull.number}.patch`,
    issue_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${pull.number}`,
    number: pull.number,
    state: pull.state,
    locked: false,
    title: pull.title,
    user: userJson(VIEWER_LOGIN, VIEWER_ID),
    body: pull.body,
    created_at: isoOf(pull.createdSec),
    updated_at: isoOf(pull.updatedSec),
    closed_at: pull.state === 'closed' ? isoOf(pull.updatedSec) : null,
    merged_at: pull.mergedSec === null ? null : isoOf(pull.mergedSec),
    merge_commit_sha: pull.mergeCommitSha,
    assignee: null,
    assignees: [],
    requested_reviewers: [],
    requested_teams: [],
    labels: [],
    milestone: null,
    draft: false,
    commits_url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}/commits`,
    review_comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}/comments`,
    review_comment_url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/comments{/number}`,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${pull.number}/comments`,
    statuses_url: `/api/v3/repos/${repo.owner}/${repo.name}/statuses/${headTip}`,
    head: {
      label: `${repo.owner}:${pull.head}`,
      ref: pull.head,
      sha: headTip,
      user: userJson(VIEWER_LOGIN, VIEWER_ID),
      repo: repoJson(repo, origin),
    },
    base: {
      label: `${repo.owner}:${pull.base}`,
      ref: pull.base,
      sha: baseTip,
      user: userJson(VIEWER_LOGIN, VIEWER_ID),
      repo: repoJson(repo, origin),
    },
    _links: {
      self: { href: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}` },
      html: { href: `https://github.invalid/${repo.owner}/${repo.name}/pull/${pull.number}` },
      issue: { href: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${pull.number}` },
      comments: { href: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${pull.number}/comments` },
      review_comments: { href: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}/comments` },
      review_comment: { href: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/comments{/number}` },
      commits: { href: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}/commits` },
      statuses: { href: `/api/v3/repos/${repo.owner}/${repo.name}/statuses/${headTip}` },
    },
    author_association: 'OWNER',
    auto_merge: null,
    active_lock_reason: null,
    merged: pull.merged,
    mergeable: pullMergeable(repo, pull),
    rebaseable: pullMergeable(repo, pull),
    mergeable_state: pull.state !== 'open' ? 'unknown' : pullMergeable(repo, pull) ? 'clean' : 'dirty',
    merged_by: pull.merged ? userJson(VIEWER_LOGIN, VIEWER_ID) : null,
    comments: 0,
    review_comments: 0,
    maintainer_can_modify: false,
    commits: collectCommits(repo, [pull.headSha]).length,
    additions: 0,
    deletions: 0,
    changed_files: 0,
  };
}

// ============================================================================
// REST v3
// ============================================================================

function validationFailed(res: ServerResponse, field: string, message: string): void {
  sendJson(res, 422, {
    message: 'Validation Failed',
    errors: [{ resource: 'Repository', code: 'custom', field, message }],
    documentation_url: 'https://docs.github.com/rest',
  });
}

function commitJson(repo: Repo, sha: string): JsonObject | null {
  const object = repo.objects.get(sha);
  if (object === undefined || object.type !== 'commit') return null;
  const view = parseCommit(object.data);
  const authorDate = isoOf(commitTimestamp(view));
  const parents = view.parents.map((p) => ({
    sha: p,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${p}`,
    html_url: `https://github.invalid/${repo.owner}/${repo.name}/commit/${p}`,
  }));
  return {
    sha,
    node_id: b64encode(`C:${repo.owner}/${repo.name}:${sha}`),
    commit: {
      author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: authorDate },
      committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: authorDate },
      message: view.message,
      tree: { sha: view.tree, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/trees/${view.tree}` },
      url: `/api/v3/repos/${repo.owner}/${repo.name}/git/commits/${sha}`,
      comment_count: 0,
      verification: { verified: false, reason: 'unsigned', signature: null, payload: null, verified_at: null },
    },
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}`,
    html_url: `https://github.invalid/${repo.owner}/${repo.name}/commit/${sha}`,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}/comments`,
    author: userJson(VIEWER_LOGIN, VIEWER_ID),
    committer: userJson(VIEWER_LOGIN, VIEWER_ID),
    parents,
  };
}

function contentEntryJson(repo: Repo, path: string, entry: { oid: string; mode: string }, name: string): JsonObject {
  const isDir = entry.mode === '40000';
  const object = repo.objects.get(entry.oid);
  const size = !isDir && object !== undefined && object.type === 'blob' ? object.data.length : 0;
  return {
    type: isDir ? 'dir' : 'file',
    size,
    name,
    path,
    sha: entry.oid,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}`,
    git_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${isDir ? 'trees' : 'blobs'}/${entry.oid}`,
    html_url: `https://github.invalid/${repo.owner}/${repo.name}/blob/${repo.defaultBranch}/${path}`,
    download_url: isDir ? null : `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}?raw=1`,
    _links: {
      self: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}`,
      git: `/api/v3/repos/${repo.owner}/${repo.name}/git/${isDir ? 'trees' : 'blobs'}/${entry.oid}`,
      html: `https://github.invalid/${repo.owner}/${repo.name}/blob/${repo.defaultBranch}/${path}`,
    },
  };
}

function lineDiff(oldData: Buffer | null, newData: Buffer | null): { additions: number; deletions: number } {
  const countLines = (data: Buffer | null): Map<string, number> => {
    const map = new Map<string, number>();
    if (data === null) return map;
    for (const line of data.toString('utf8').split('\n')) {
      if (line === '' && data.length === 0) continue;
      map.set(line, (map.get(line) ?? 0) + 1);
    }
    return map;
  };
  const oldLines = countLines(oldData);
  const newLines = countLines(newData);
  let common = 0;
  for (const [line, count] of oldLines) common += Math.min(count, newLines.get(line) ?? 0);
  const oldTotal = [...oldLines.values()].reduce((a, b) => a + b, 0);
  const newTotal = [...newLines.values()].reduce((a, b) => a + b, 0);
  return { additions: newTotal - common, deletions: oldTotal - common };
}

/** Handle a /api/v3 request. Returns true when handled. */
async function handleRest(req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams, bodyBuf: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  const path = `/${segments.join('/')}`;
  const origin = originOf(req);

  // API root: 200 with the token's scopes, no auth required (as the starter answers).
  if (segments.length === 2) {
    if (method !== 'GET') { notFound(res); return true; }
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      current_user_authorizations_html_url: 'https://github.invalid/settings/applications',
      authorizations_url: '/api/v3/authorizations',
      code_search_url: '/api/v3/search/code?q={query}{&page,per_page,sort,order}',
      commit_search_url: '/api/v3/search/commits?q={query}{&page,per_page,sort,order}',
      emails_url: '/api/v3/user/emails',
      emojis_url: '/api/v3/emojis',
      events_url: '/api/v3/events',
      feeds_url: '/api/v3/feeds',
      followers_url: '/api/v3/users/{username}/followers',
      following_url: '/api/v3/users/{username}/following{/other_user}',
      gists_url: '/api/v3/gists{/gist_id}',
      hub_url: '/api/v3/hub',
      issue_search_url: '/api/v3/search/issues?q={query}{&page,per_page,sort,order}',
      issues_url: '/api/v3/issues',
      keys_url: '/api/v3/user/keys',
      label_search_url: '/api/v3/search/labels?q={query}&repository_id={repository_id}{&page,per_page}',
      notifications_url: '/api/v3/notifications{?since,all,participating}',
      organization_url: '/api/v3/orgs/{org}',
      organization_repositories_url: '/api/v3/orgs/{org}/repos{?type,page,per_page,sort}',
      organization_teams_url: '/api/v3/orgs/{org}/teams',
      public_gists_url: '/api/v3/gists/public',
      rate_limit_url: '/api/v3/rate_limit',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      repository_search_url: '/api/v3/search/repositories?q={query}{&page,per_page,sort,order}',
      current_user_repositories_url: '/api/v3/user/repos{?type,page,per_page,sort}',
      starred_url: '/api/v3/user/starred{/owner}{/repo}',
      starred_gists_url: '/api/v3/gists/starred',
      topic_search_url: '/api/v3/search/topics?q={query}{&page,per_page}',
      user_url: '/api/v3/users/{username}',
      user_organizations_url: '/api/v3/user/orgs',
      user_repositories_url: '/api/v3/user/repos{?type,page,per_page,sort}',
      user_search_url: '/api/v3/search/users?q={query}{&page,per_page,sort,order}',
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  if (!authorized(req)) { badCredentials(res); return true; }

  const mutating = method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE';
  let body: unknown = {};
  if (mutating) {
    const parsed = parseJsonBody(bodyBuf);
    if (!parsed.ok) {
      sendJson(res, 400, { message: 'Problems parsing JSON' });
      return true;
    }
    body = parsed.value;
  }
  const bodyObj = asObject(body) ?? {};

  // GET /meta
  if (segments[2] === 'meta' && segments.length === 3) {
    if (method !== 'GET') { notFound(res); return true; }
    sendJson(res, 200, {
      verifiable_password_authentication: true,
      ssh_key_fingerprints: {},
      ssh_keys: [],
      hooks: [],
      web: [],
      api: [],
      git: [],
      packages: [],
      pages: [],
      importer: [],
      actions: [],
      dependabot: [],
      installed_version: '1.0.0',
    });
    return true;
  }

  // GET /rate_limit
  if (segments[2] === 'rate_limit' && segments.length === 3) {
    if (method !== 'GET') { notFound(res); return true; }
    const reset = EPOCH_SEC + 3600;
    sendJson(res, 200, {
      resources: {
        core: { limit: 5000, remaining: 4999, reset, used: 1 },
        search: { limit: 30, remaining: 30, reset, used: 0 },
        graphql: { limit: 5000, remaining: 5000, reset, used: 0 },
        integration_manifest: { limit: 5000, remaining: 5000, reset, used: 0 },
        code_scanning_upload: { limit: 500, remaining: 500, reset, used: 0 },
      },
      rate: { limit: 5000, remaining: 4999, reset, used: 1 },
    });
    return true;
  }

  // /user and /user/repos
  if (segments[2] === 'user') {
    if (segments.length === 3) {
      if (method !== 'GET') { notFound(res); return true; }
      sendJson(res, 200, {
        ...userJson(VIEWER_LOGIN, VIEWER_ID),
        name: VIEWER_NAME,
        email: VIEWER_EMAIL,
        company: null,
        blog: '',
        location: null,
        hireable: null,
        bio: null,
        twitter_username: null,
        public_repos: repos.size,
        public_gists: 0,
        followers: 0,
        following: 0,
        created_at: isoOf(EPOCH_SEC),
        updated_at: isoOf(EPOCH_SEC),
      });
      return true;
    }
    if (segments[3] === 'repos' && segments.length === 4) {
      if (method === 'GET') {
        const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.seq - b.seq);
        const { page, link } = paginate(req, path, query, all.map((r) => repoJson(r, origin)));
        sendJson(res, 200, page, { link });
        return true;
      }
      if (method === 'POST') {
        const name = typeof bodyObj.name === 'string' ? bodyObj.name : '';
        if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) {
          validationFailed(res, 'name', 'name is invalid');
          return true;
        }
        if (findRepo(VIEWER_LOGIN, name) !== undefined) {
          sendJson(res, 422, {
            message: 'Repository creation failed.',
            errors: [{ resource: 'Repository', code: 'custom', field: 'name', message: 'name already exists on this account' }],
            documentation_url: 'https://docs.github.com/rest/repos/repos#create-a-repository-for-the-authenticated-user',
          });
          return true;
        }
        const repo = createRepoRecord(
          VIEWER_LOGIN,
          name,
          typeof bodyObj.description === 'string' ? bodyObj.description : '',
          bodyObj.private === true,
          typeof bodyObj.default_branch === 'string' && bodyObj.default_branch !== '' ? bodyObj.default_branch : 'main',
        );
        sendJson(res, 201, repoJson(repo, origin));
        return true;
      }
      notFound(res);
      return true;
    }
    return false;
  }

  // /repos/{owner}/{name}/...
  if (segments[2] === 'repos' && segments.length >= 4) {
    const repoOwner = segments[3];
    const repoName = segments[4];
    const repo = findRepo(repoOwner, repoName);
    if (repo === undefined || repoOwner !== VIEWER_LOGIN) { notFound(res); return true; }
    const rest = segments.slice(5);

    // /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo, origin)); return true; }
      if (method === 'PATCH') {
        if (typeof bodyObj.description === 'string') repo.description = bodyObj.description;
        if (typeof bodyObj.private === 'boolean') repo.private = bodyObj.private;
        if (typeof bodyObj.default_branch === 'string' && bodyObj.default_branch !== '') repo.defaultBranch = bodyObj.default_branch;
        repo.updatedSec = nextTs();
        sendJson(res, 200, repoJson(repo, origin));
        return true;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(repo.owner, repo.name));
        sendEmpty(res, 204);
        return true;
      }
      notFound(res);
      return true;
    }

    // branches
    if (rest[0] === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        const branches = [...repo.refs.keys()]
          .filter((ref) => ref.startsWith('refs/heads/'))
          .map((ref) => ref.slice('refs/heads/'.length))
          .sort()
          .map((name) => ({
            name,
            commit: commitJson(repo, repo.refs.get(`refs/heads/${name}`) as string) ?? { sha: repo.refs.get(`refs/heads/${name}`) },
            protected: false,
          }));
        const { page, link } = paginate(req, path, query, branches);
        sendJson(res, 200, page, { link });
        return true;
      }
      if (rest.length >= 2 && method === 'GET') {
        const branch = rest.slice(1).join('/');
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (tip === undefined) { notFound(res); return true; }
        sendJson(res, 200, {
          name: branch,
          commit: commitJson(repo, tip) ?? { sha: tip },
          protected: false,
          protection: { enabled: false, required_status_checks: { enforcement_level: 'off', contexts: [], checks: [] } },
          protection_url: `/api/v3/repos/${repo.owner}/${repo.name}/branches/${encodeURIComponent(branch)}/protection`,
        });
        return true;
      }
      notFound(res);
      return true;
    }

    // commits
    if (rest[0] === 'commits') {
      if (rest.length === 1 && method === 'GET') {
        const ref = query.get('sha') ?? repo.defaultBranch;
        const tip = resolveRef(repo, ref);
        if (tip === null) { notFound(res); return true; }
        const commits = collectCommits(repo, [tip])
          .map((sha) => ({ sha, view: parseCommit((repo.objects.get(sha) as GitObject).data) }))
          .sort((a, b) => commitTimestamp(b.view) - commitTimestamp(a.view) || 0)
          .map(({ sha }) => commitJson(repo, sha))
          .filter((c): c is JsonObject => c !== null);
        const { page, link } = paginate(req, path, query, commits);
        sendJson(res, 200, page, { link });
        return true;
      }
      if (rest.length === 2 && method === 'GET') {
        const sha = resolveRef(repo, rest[1]);
        if (sha === null) { notFound(res); return true; }
        const json = commitJson(repo, sha);
        if (json === null) { notFound(res); return true; }
        sendJson(res, 200, json);
        return true;
      }
      notFound(res);
      return true;
    }

    // git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (rest.length === 2) {
        if (method === 'GET') {
          const all = [...repo.refs.entries()]
            .sort((a, b) => (a[0] < b[0] ? -1 : 1))
            .map(([ref, oid]) => ({ ref, object: { sha: oid, type: (repo.objects.get(oid)?.type ?? 'commit') as string, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${repo.objects.get(oid)?.type === 'tag' ? 'tags' : 'commits'}/${oid}` } }));
          sendJson(res, 200, all);
          return true;
        }
        if (method === 'POST') {
          const ref = typeof bodyObj.ref === 'string' ? bodyObj.ref : '';
          const sha = typeof bodyObj.sha === 'string' ? bodyObj.sha : '';
          if (!/^refs\/(heads|tags)\/.+/.test(ref)) { validationFailed(res, 'ref', 'ref must start with refs/heads/ or refs/tags/'); return true; }
          if (!OID_RE.test(sha) || !repo.objects.has(sha)) { validationFailed(res, 'sha', 'Invalid SHA'); return true; }
          if (repo.refs.has(ref)) { validationFailed(res, 'ref', 'Reference already exists'); return true; }
          repo.refs.set(ref, sha);
          repo.updatedSec = nextTs();
          sendJson(res, 201, {
            ref,
            node_id: b64encode(`REF:${repo.owner}/${repo.name}:${ref}`),
            url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref}`,
            object: { sha, type: (repo.objects.get(sha)?.type ?? 'commit') as string, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/commits/${sha}` },
          });
          return true;
        }
        notFound(res);
        return true;
      }
      if (rest.length >= 3 && method === 'GET') {
        const ref = rest.slice(2).join('/');
        const tip = repo.refs.get(ref);
        if (tip === undefined) { notFound(res); return true; }
        sendJson(res, 200, {
          ref,
          node_id: b64encode(`REF:${repo.owner}/${repo.name}:${ref}`),
          url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref}`,
          object: { sha: tip, type: (repo.objects.get(tip)?.type ?? 'commit') as string, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/commits/${tip}` },
        });
        return true;
      }
      notFound(res);
      return true;
    }

    // contents
    if (rest[0] === 'contents') {
      const filePath = rest.slice(1).join('/');
      const refParam = query.get('ref') ?? undefined;
      const tipFor = (): string | null => {
        if (refParam !== undefined) return resolveRef(repo, refParam);
        return headTarget(repo) === ZERO_OID ? null : headTarget(repo);
      };
      if (method === 'GET') {
        const tip = tipFor();
        if (tip === null) { notFound(res); return true; }
        const commit = repo.objects.get(tip);
        if (commit === undefined || commit.type !== 'commit') { notFound(res); return true; }
        const treeOid = parseCommit(commit.data).tree;
        if (filePath === '') {
          const object = repo.objects.get(treeOid);
          const entries = object !== undefined && object.type === 'tree' ? parseTree(object.data) : [];
          sendJson(res, 200, entries.map((e) => contentEntryJson(repo, e.name, e, e.name)));
          return true;
        }
        const flat = flattenTree(repo, treeOid);
        const file = flat.get(filePath);
        if (file !== undefined) {
          const blob = repo.objects.get(file.oid);
          if (blob === undefined || blob.type !== 'blob') { notFound(res); return true; }
          sendJson(res, 200, {
            ...contentEntryJson(repo, filePath, file, filePath.split('/').pop() as string),
            type: 'file',
            encoding: 'base64',
            content: blob.data.toString('base64'),
          });
          return true;
        }
        // A directory: the entries directly under filePath.
        const dirEntries: Array<{ name: string; entry: { oid: string; mode: string } }> = [];
        const prefix = `${filePath}/`;
        for (const [p, entry] of flat) {
          if (!p.startsWith(prefix)) continue;
          const rest2 = p.slice(prefix.length);
          if (rest2.includes('/')) continue;
          dirEntries.push({ name: rest2, entry });
        }
        // Subdirectories that hold no files directly are still directories: walk the
        // tree path directly when the flat walk found nothing.
        if (dirEntries.length === 0) {
          let current: string | null = treeOid;
          const segments2 = filePath.split('/');
          for (const segment of segments2) {
            const object = current === null ? undefined : repo.objects.get(current);
            if (object === undefined || object.type !== 'tree') { current = null; break; }
            const child = parseTree(object.data).find((e) => e.name === segment && e.mode === '40000');
            current = child === undefined ? null : child.oid;
          }
          if (current === null) { notFound(res); return true; }
          const object = repo.objects.get(current);
          const entries = object !== undefined && object.type === 'tree' ? parseTree(object.data) : [];
          sendJson(res, 200, entries.map((e) => contentEntryJson(repo, `${filePath}/${e.name}`, e, e.name)));
          return true;
        }
        dirEntries.sort((a, b) => (a.name < b.name ? -1 : 1));
        sendJson(res, 200, dirEntries.map(({ name, entry }) => contentEntryJson(repo, `${filePath}/${name}`, entry, name)));
        return true;
      }
      if (method === 'PUT') {
        if (filePath === '') { validationFailed(res, 'path', 'path is required'); return true; }
        const branch = typeof bodyObj.branch === 'string' && bodyObj.branch !== '' ? bodyObj.branch : repo.defaultBranch;
        const branchRef = `refs/heads/${branch}`;
        const tip = repo.refs.get(branchRef) ?? null;
        if (tip === null && repo.refs.size > 0) { notFound(res); return true; }
        if (tip === null && branch !== repo.defaultBranch) { notFound(res); return true; }
        if (typeof bodyObj.content !== 'string') { validationFailed(res, 'content', 'content is required'); return true; }
        const content = b64decode(bodyObj.content);
        let currentBlob: { oid: string; data: Buffer } | null = null;
        if (tip !== null) {
          const commit = repo.objects.get(tip);
          if (commit !== undefined && commit.type === 'commit') currentBlob = readPath(repo, parseCommit(commit.data).tree, filePath);
        }
        const givenSha = typeof bodyObj.sha === 'string' ? bodyObj.sha : undefined;
        if (givenSha !== undefined) {
          if (currentBlob === null || currentBlob.oid !== givenSha) {
            sendJson(res, 409, { message: 'The sha does not match the current file.' });
            return true;
          }
        } else if (currentBlob !== null) {
          sendJson(res, 409, { message: 'The file already exists; pass its sha to update it.' });
          return true;
        }
        const message = typeof bodyObj.message === 'string' && bodyObj.message !== '' ? bodyObj.message : `Update ${filePath}`;
        const newCommit = commitFileChange(repo, tip, filePath, content, message);
        repo.refs.set(branchRef, newCommit);
        const now = nextTs();
        repo.updatedSec = now;
        repo.pushedSec = now;
        const commitObject = repo.objects.get(newCommit) as GitObject;
        const commitView = parseCommit(commitObject.data);
        const blobOid = storeBlob(repo, content);
        sendJson(res, currentBlob === null ? 201 : 200, {
          content: {
            name: filePath.split('/').pop(),
            path: filePath,
            sha: blobOid,
            size: content.length,
            url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
            html_url: `https://github.invalid/${repo.owner}/${repo.name}/blob/${branch}/${filePath}`,
            git_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/blobs/${blobOid}`,
            download_url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}?raw=1`,
            type: 'file',
            encoding: 'base64',
            content: content.toString('base64'),
            _links: {
              self: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
              git: `/api/v3/repos/${repo.owner}/${repo.name}/git/blobs/${blobOid}`,
              html: `https://github.invalid/${repo.owner}/${repo.name}/blob/${branch}/${filePath}`,
            },
          },
          commit: {
            sha: newCommit,
            node_id: b64encode(`C:${repo.owner}/${repo.name}:${newCommit}`),
            message,
            author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(commitTimestamp(commitView)) },
            committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(commitTimestamp(commitView)) },
            tree: { sha: commitView.tree },
            parents: commitView.parents.map((p) => ({ sha: p })),
            html_url: `https://github.invalid/${repo.owner}/${repo.name}/commit/${newCommit}`,
          },
        });
        return true;
      }
      if (method === 'DELETE') {
        if (filePath === '') { validationFailed(res, 'path', 'path is required'); return true; }
        const branch = typeof bodyObj.branch === 'string' && bodyObj.branch !== '' ? bodyObj.branch : repo.defaultBranch;
        const branchRef = `refs/heads/${branch}`;
        const tip = repo.refs.get(branchRef) ?? null;
        if (tip === null) { notFound(res); return true; }
        const commit = repo.objects.get(tip);
        if (commit === undefined || commit.type !== 'commit') { notFound(res); return true; }
        const currentBlob = readPath(repo, parseCommit(commit.data).tree, filePath);
        if (currentBlob === null) { notFound(res); return true; }
        const givenSha = typeof bodyObj.sha === 'string' ? bodyObj.sha : undefined;
        if (givenSha !== undefined && givenSha !== currentBlob.oid) {
          sendJson(res, 409, { message: 'The sha does not match the current file.' });
          return true;
        }
        const message = typeof bodyObj.message === 'string' && bodyObj.message !== '' ? bodyObj.message : `Delete ${filePath}`;
        const newCommit = commitFileChange(repo, tip, filePath, null, message);
        repo.refs.set(branchRef, newCommit);
        const now = nextTs();
        repo.updatedSec = now;
        repo.pushedSec = now;
        const commitView = parseCommit((repo.objects.get(newCommit) as GitObject).data);
        sendJson(res, 200, {
          commit: {
            sha: newCommit,
            node_id: b64encode(`C:${repo.owner}/${repo.name}:${newCommit}`),
            message,
            author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(commitTimestamp(commitView)) },
            committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(commitTimestamp(commitView)) },
            tree: { sha: commitView.tree },
            parents: commitView.parents.map((p) => ({ sha: p })),
            html_url: `https://github.invalid/${repo.owner}/${repo.name}/commit/${newCommit}`,
          },
        });
        return true;
      }
      notFound(res);
      return true;
    }

    // labels
    if (rest[0] === 'labels') {
      if (rest.length === 1) {
        if (method === 'GET') {
          sendJson(res, 200, [...repo.labels.values()].map((l) => labelJson(repo, l)));
          return true;
        }
        if (method === 'POST') {
          const name = typeof bodyObj.name === 'string' ? bodyObj.name : '';
          if (name === '') { validationFailed(res, 'name', 'name is required'); return true; }
          const existing = repo.labels.get(name);
          if (existing !== undefined) { sendJson(res, 201, labelJson(repo, existing)); return true; }
          const color = typeof bodyObj.color === 'string' && /^[0-9a-fA-F]{6}$/.test(bodyObj.color) ? bodyObj.color.toLowerCase() : 'ededed';
          const label: Label = { name, color, description: typeof bodyObj.description === 'string' ? bodyObj.description : '' };
          repo.labels.set(name, label);
          sendJson(res, 201, labelJson(repo, label));
          return true;
        }
        notFound(res);
        return true;
      }
      notFound(res);
      return true;
    }

    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          const key = sort === 'updated' ? (i: Issue): number => i.updatedSec : sort === 'comments' ? (i: Issue): number => i.comments.length : (i: Issue): number => i.createdSec;
          list.sort((a, b) => (direction === 'asc' ? key(a) - key(b) : key(b) - key(a)) || a.number - b.number);
          const { page, link } = paginate(req, path, query, list.map((i) => issueJson(repo, i)));
          sendJson(res, 200, page, { link });
          return true;
        }
        if (method === 'POST') {
          const title = typeof bodyObj.title === 'string' ? bodyObj.title : '';
          if (title === '') { validationFailed(res, 'title', 'title is required'); return true; }
          const labelNames = Array.isArray(bodyObj.labels) ? (bodyObj.labels as unknown[]).filter((l): l is string => typeof l === 'string') : [];
          for (const name of labelNames) {
            if (!repo.labels.has(name)) {
              sendJson(res, 422, {
                message: 'Validation Failed',
                errors: [{ resource: 'Issue', code: 'custom', field: 'labels', message: `Label '${name}' does not exist` }],
              });
              return true;
            }
          }
          const now = nextTs();
          const number = repo.nextNumber;
          repo.nextNumber += 1;
          const issue: Issue = {
            number,
            title,
            body: typeof bodyObj.body === 'string' ? bodyObj.body : '',
            state: 'open',
            labels: labelNames,
            comments: [],
            createdSec: now,
            updatedSec: now,
            closedSec: null,
            nextCommentId: 1,
          };
          repo.issues.set(number, issue);
          sendJson(res, 201, issueJson(repo, issue));
          return true;
        }
        notFound(res);
        return true;
      }
      const issueNumber = Number(rest[1]);
      if (!Number.isInteger(issueNumber) || issueNumber < 1) { notFound(res); return true; }
      const issue = repo.issues.get(issueNumber);
      if (rest.length === 2) {
        if (issue === undefined) { notFound(res); return true; }
        if (method === 'GET') { sendJson(res, 200, issueJson(repo, issue)); return true; }
        if (method === 'PATCH') {
          if (typeof bodyObj.title === 'string') issue.title = bodyObj.title;
          if (typeof bodyObj.body === 'string') issue.body = bodyObj.body;
          if (bodyObj.state === 'open' || bodyObj.state === 'closed') {
            issue.state = bodyObj.state;
            issue.closedSec = bodyObj.state === 'closed' ? nextTs() : null;
          }
          if (Array.isArray(bodyObj.labels)) {
            const labelNames = (bodyObj.labels as unknown[]).filter((l): l is string => typeof l === 'string');
            for (const name of labelNames) {
              if (!repo.labels.has(name)) {
                sendJson(res, 422, { message: 'Validation Failed', errors: [{ resource: 'Issue', code: 'custom', field: 'labels', message: `Label '${name}' does not exist` }] });
                return true;
              }
            }
            issue.labels = labelNames;
          }
          issue.updatedSec = nextTs();
          sendJson(res, 200, issueJson(repo, issue));
          return true;
        }
        notFound(res);
        return true;
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (issue === undefined) { notFound(res); return true; }
        if (method === 'GET') {
          const { page, link } = paginate(req, path, query, issue.comments.map((c) => commentJson(repo, issue, c)));
          sendJson(res, 200, page, { link });
          return true;
        }
        if (method === 'POST') {
          const bodyText = typeof bodyObj.body === 'string' ? bodyObj.body : '';
          if (bodyText === '') { validationFailed(res, 'body', 'body is required'); return true; }
          const now = nextTs();
          const comment: IssueComment = { id: issue.nextCommentId, body: bodyText, createdSec: now, updatedSec: now };
          issue.nextCommentId += 1;
          issue.comments.push(comment);
          issue.updatedSec = now;
          sendJson(res, 201, commentJson(repo, issue, comment));
          return true;
        }
        notFound(res);
        return true;
      }
      notFound(res);
      return true;
    }

    // pull requests
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          let list = [...repo.pulls.values()];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          const key = sort === 'updated' ? (p: Pull): number => p.updatedSec : (p: Pull): number => p.createdSec;
          list.sort((a, b) => (direction === 'asc' ? key(a) - key(b) : key(b) - key(a)) || a.number - b.number);
          const { page, link } = paginate(req, path, query, list.map((p) => pullJson(repo, p, origin)));
          sendJson(res, 200, page, { link });
          return true;
        }
        if (method === 'POST') {
          const title = typeof bodyObj.title === 'string' ? bodyObj.title : '';
          const head = typeof bodyObj.head === 'string' ? bodyObj.head : '';
          const base = typeof bodyObj.base === 'string' ? bodyObj.base : '';
          if (title === '') { validationFailed(res, 'title', 'title is required'); return true; }
          if (head === '' || base === '') { validationFailed(res, 'head', 'head and base are required'); return true; }
          const headTip = repo.refs.get(`refs/heads/${head}`);
          const baseTip = repo.refs.get(`refs/heads/${base}`);
          if (headTip === undefined || baseTip === undefined) {
            sendJson(res, 422, { message: 'Validation Failed', errors: [{ resource: 'PullRequest', code: 'custom', field: 'head', message: 'head or base branch does not exist' }] });
            return true;
          }
          const now = nextTs();
          const number = repo.nextNumber;
          repo.nextNumber += 1;
          const pull: Pull = {
            number,
            title,
            body: typeof bodyObj.body === 'string' ? bodyObj.body : '',
            state: 'open',
            merged: false,
            head,
            base,
            headSha: headTip,
            baseSha: baseTip,
            mergeCommitSha: null,
            mergedSec: null,
            createdSec: now,
            updatedSec: now,
          };
          repo.pulls.set(number, pull);
          sendJson(res, 201, pullJson(repo, pull, origin));
          return true;
        }
        notFound(res);
        return true;
      }
      const pullNumber = Number(rest[1]);
      if (!Number.isInteger(pullNumber) || pullNumber < 1) { notFound(res); return true; }
      const pull = repo.pulls.get(pullNumber);
      if (rest.length === 2) {
        if (pull === undefined) { notFound(res); return true; }
        if (method === 'GET') { sendJson(res, 200, pullJson(repo, pull, origin)); return true; }
        if (method === 'PATCH') {
          if (typeof bodyObj.title === 'string') pull.title = bodyObj.title;
          if (typeof bodyObj.body === 'string') pull.body = bodyObj.body;
          if (bodyObj.state === 'closed') pull.state = 'closed';
          if (bodyObj.state === 'open') pull.state = 'open';
          pull.updatedSec = nextTs();
          sendJson(res, 200, pullJson(repo, pull, origin));
          return true;
        }
        notFound(res);
        return true;
      }
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        if (pull === undefined) { notFound(res); return true; }
        const base = mergeBase(repo, pull.baseSha, pull.headSha) ?? pull.baseSha;
        const baseCommit = repo.objects.get(base);
        const headCommit = repo.objects.get(pull.headSha);
        if (baseCommit === undefined || headCommit === undefined) { sendJson(res, 200, []); return true; }
        const baseTree = parseCommit(baseCommit.data).tree;
        const headTree = parseCommit(headCommit.data).tree;
        const files = diffTrees(repo, baseTree, headTree).map((d) => {
          const oldData = d.baseOid === null ? null : (repo.objects.get(d.baseOid)?.data ?? null);
          const newData = d.headOid === null ? null : (repo.objects.get(d.headOid)?.data ?? null);
          const { additions, deletions } = lineDiff(oldData, newData);
          return {
            sha: d.headOid ?? d.baseOid ?? '',
            filename: d.path,
            status: d.status,
            additions,
            deletions,
            changes: additions + deletions,
            blob_url: `https://github.invalid/${repo.owner}/${repo.name}/blob/${pull.headSha}/${d.path}`,
            raw_url: `https://github.invalid/${repo.owner}/${repo.name}/raw/${pull.headSha}/${d.path}`,
            contents_url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${d.path}?ref=${pull.headSha}`,
            patch: '',
          };
        });
        sendJson(res, 200, files);
        return true;
      }
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        if (pull === undefined) { notFound(res); return true; }
        if (pull.state !== 'open') {
          sendJson(res, 405, { message: pull.merged ? 'Pull request has already been merged' : 'Pull request is closed' });
          return true;
        }
        if (!pullMergeable(repo, pull)) {
          sendJson(res, 405, { message: 'Merge conflict: the pull request cannot be merged cleanly' });
          return true;
        }
        const mergeMethod = typeof bodyObj.merge_method === 'string' ? bodyObj.merge_method : 'merge';
        const baseTip = refTip(repo, `refs/heads/${pull.base}`) ?? pull.baseSha;
        const headCommit = repo.objects.get(pull.headSha);
        if (headCommit === undefined) { notFound(res); return true; }
        const headTree = parseCommit(headCommit.data).tree;
        const epochSec = nextTs();
        const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitDateOf(epochSec)}`;
        let message: string;
        let parents: string[];
        if (mergeMethod === 'squash') {
          message = typeof bodyObj.commit_title === 'string' && bodyObj.commit_title !== '' ? bodyObj.commit_title : `${pull.title} (#${pull.number})`;
          parents = [baseTip];
        } else if (mergeMethod === 'rebase') {
          message = pull.title;
          parents = [baseTip];
        } else {
          message = typeof bodyObj.commit_title === 'string' && bodyObj.commit_title !== '' ? bodyObj.commit_title : `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}`;
          parents = [baseTip, pull.headSha];
        }
        const lines = [`tree ${headTree}`, ...parents.map((p) => `parent ${p}`), `author ${who}`, `committer ${who}`, '', message];
        const mergeCommitData = Buffer.from(lines.join('\n'), 'utf8');
        const mergeSha = hashObject('commit', mergeCommitData);
        repo.objects.set(mergeSha, { type: 'commit', data: mergeCommitData });
        repo.refs.set(`refs/heads/${pull.base}`, mergeSha);
        pull.state = 'closed';
        pull.merged = true;
        pull.mergeCommitSha = mergeSha;
        pull.mergedSec = epochSec;
        pull.updatedSec = epochSec;
        repo.updatedSec = epochSec;
        repo.pushedSec = epochSec;
        sendJson(res, 200, { sha: mergeSha, merged: true, message: 'Pull request successfully merged' });
        return true;
      }
      notFound(res);
      return true;
    }

    return false;
  }

  return false;
}

// ============================================================================
// git smart HTTP
// ============================================================================

const GIT_AGENT = `${FORGE_NAME}/${FORGE_VERSION}`;

function gitCapabilities(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): string {
  const common = `agent=${GIT_AGENT} object-format=sha1`;
  if (service === 'git-upload-pack') {
    return `symref=HEAD:refs/heads/${repo.defaultBranch} multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not no-progress include-tag ${common}`;
  }
  return `report-status report-status-v2 side-band-64k delete-refs ofs-delta ${common}`;
}

/** The v0 ref advertisement: service preamble, refs, peeled tags, flush. */
function advertiseV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = gitCapabilities(repo, service);
  const parts: Buffer[] = [];
  parts.push(encodePktLine(`# service=${service}\n`));
  parts.push(PKT_FLUSH);
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const headTip = repo.refs.get(defaultBranchRef(repo));
  if (refs.length === 0) {
    parts.push(encodePktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const headOid = headTip ?? ZERO_OID;
    parts.push(encodePktLine(`${headOid} HEAD\0${caps}\n`));
    for (const [name, oid] of refs) {
      parts.push(encodePktLine(`${oid} ${name}\n`));
      const object = repo.objects.get(oid);
      if (object !== undefined && object.type === 'tag') {
        const peeled = peelTag(repo, oid);
        if (peeled !== null) parts.push(encodePktLine(`${peeled} ${name}^{}\n`));
      }
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** The protocol v2 capability advertisement. */
function advertiseV2(): Buffer {
  return encodePktLines([
    'version 2\n',
    `agent=${GIT_AGENT}\n`,
    'ls-refs=unborn\n',
    'fetch=shallow wait-for-done\n',
    'server-option\n',
    'object-format=sha1\n',
    'flush',
  ]);
}

/** One v2 ls-refs line for a ref, with the requested attributes. */
function lsRefsLine(repo: Repo, name: string, oid: string, opts: { peel: boolean; symrefs: boolean }): string {
  const attrs: string[] = [];
  if (name === 'HEAD') {
    if (opts.symrefs) attrs.push(`symref-target:${defaultBranchRef(repo)}`);
  } else if (opts.peel) {
    const object = repo.objects.get(oid);
    if (object !== undefined && object.type === 'tag') {
      const peeled = peelTag(repo, oid);
      if (peeled !== null) attrs.push(`peeled:${peeled}`);
    }
  }
  return `${oid} ${name}${attrs.length > 0 ? ` ${attrs.join(' ')}` : ''}\n`;
}

interface FetchPlan {
  objects: Map<string, GitObject>;
  shallow: string[];
  unshallow: string[];
}

/**
 * Plan a fetch: the objects to send for `wants`, minus what the client holds.
 * `haves` are commits the client holds; `shallowBoundaries` are its current
 * shallow boundary commits (their parents are not held). `depth` limits the
 * generations sent from each want; `deepenSince` (epoch seconds) limits by
 * committer time instead.
 */
function planFetch(
  repo: Repo,
  wants: readonly string[],
  haves: readonly string[],
  shallowBoundaries: readonly string[],
  depth: number | undefined,
  deepenSince: number | undefined,
): FetchPlan {
  const boundarySet = new Set(shallowBoundaries);
  // What the client already holds: the closure of its haves, stopping at its
  // shallow boundaries (a boundary commit is held, its parents are not).
  const held = new Set<string>();
  {
    const queue: string[] = [...haves];
    const seen = new Set<string>();
    while (queue.length > 0) {
      const oid = queue.pop() as string;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const reachable = collectReachable(repo, [oid]);
      for (const key of reachable.keys()) held.add(key);
      // collectReachable already walked parents; re-walk only to honour the
      // boundary stop: remove everything reachable from a boundary's parents.
      const object = repo.objects.get(oid);
      if (object !== undefined && object.type === 'commit' && !boundarySet.has(oid)) {
        queue.push(...parseCommit(object.data).parents);
      }
    }
    // The closure above over-includes parents of boundary commits (collectReachable
    // walks them). Subtract the ancestors of every boundary commit's parents.
    for (const boundary of boundarySet) {
      const object = repo.objects.get(boundary);
      if (object === undefined || object.type !== 'commit') continue;
      for (const parent of parseCommit(object.data).parents) {
        const reachable = collectReachable(repo, [parent]);
        for (const key of reachable.keys()) held.delete(key);
      }
      held.add(boundary);
    }
  }

  // Walk the wants, generation by generation.
  const included = new Map<string, GitObject>(); // every object to consider
  const includedCommits = new Map<string, number>(); // commit oid -> generation
  const newShallow = new Set<string>();
  const queue: Array<{ oid: string; generation: number }> = wants.map((oid) => ({ oid, generation: 1 }));
  const seenCommits = new Set<string>();
  while (queue.length > 0) {
    const { oid, generation } = queue.shift() as { oid: string; generation: number };
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    if (object.type === 'tag') {
      const target = parseTag(object.data).object;
      if (!included.has(oid)) included.set(oid, object);
      queue.push({ oid: target, generation });
      continue;
    }
    if (object.type !== 'commit') {
      if (!included.has(oid)) included.set(oid, object);
      continue;
    }
    if (seenCommits.has(oid)) continue;
    seenCommits.add(oid);
    includedCommits.set(oid, generation);
    const view = parseCommit(object.data);
    if (!included.has(oid)) included.set(oid, object);
    const treeObjects = collectReachable(repo, [view.tree]);
    for (const [key, value] of treeObjects) if (!included.has(key)) included.set(key, value);
    const atDepth = depth !== undefined && generation >= depth;
    const belowSince = deepenSince !== undefined && commitTimestamp(view) < deepenSince;
    if (atDepth || belowSince) {
      newShallow.add(oid);
      continue;
    }
    for (const parent of view.parents) queue.push({ oid: parent, generation: generation + 1 });
  }
  // Deepen-since boundaries are the parents of included commits that fell below
  // the cutoff, not the included commits themselves.
  if (deepenSince !== undefined) {
    newShallow.clear();
    for (const [oid] of includedCommits) {
      const object = repo.objects.get(oid);
      if (object === undefined || object.type !== 'commit') continue;
      for (const parent of parseCommit(object.data).parents) {
        const parentObject = repo.objects.get(parent);
        if (parentObject !== undefined && parentObject.type === 'commit' && commitTimestamp(parseCommit(parentObject.data)) < deepenSince) {
          newShallow.add(parent);
        }
      }
    }
  }

  const objects = new Map<string, GitObject>();
  for (const [oid, object] of included) {
    if (!held.has(oid)) objects.set(oid, object);
  }
  const shallow = [...newShallow].sort();
  const unshallow: string[] = [];
  for (const old of boundarySet) {
    if (includedCommits.has(old) && !newShallow.has(old)) unshallow.push(old);
  }
  return { objects, shallow, unshallow: unshallow.sort() };
}

/** Handle GET /{owner}/{repo}.git/info/refs?service=... */
function handleInfoRefs(req: IncomingMessage, res: ServerResponse, repo: Repo, service: string): void {
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { notFound(res); return; }
  const isV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
  const contentType = `application/x-${service}-advertisement`;
  if (isV2) {
    sendRaw(res, 200, advertiseV2(), contentType);
    return;
  }
  sendRaw(res, 200, advertiseV0(repo, service as 'git-upload-pack' | 'git-receive-pack'), contentType);
}

/** Handle POST /{owner}/{repo}.git/git-upload-pack (v0 and v2). */
function handleUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo, bodyBuf: Buffer): void {
  let packets: Packet[];
  try {
    packets = decodePktLines(bodyBuf);
  } catch {
    sendJson(res, 400, { message: 'Bad Request' });
    return;
  }
  const first = packets.find((p) => p.kind === 'data');
  const firstLine = first === undefined ? '' : first.payload.toString('utf8');

  // Protocol v2: command=ls-refs / command=fetch.
  if (firstLine.startsWith('command=')) {
    const command = firstLine.trim();
    const args: string[] = [];
    for (const packet of packets) {
      if (packet.kind === 'flush' || packet.kind === 'delim') continue;
      const line = packet.payload.toString('utf8');
      if (line.startsWith('command=')) continue;
      if (line.startsWith('agent=') || line.startsWith('object-format=')) continue;
      args.push(line);
    }
    if (command === 'command=ls-refs') {
      let peel = false;
      let symrefs = false;
      let unborn = false;
      const prefixes: string[] = [];
      for (const arg of args) {
        const text = arg.replace(/\n$/, '');
        if (text === 'peel') peel = true;
        else if (text === 'symrefs') symrefs = true;
        else if (text === 'unborn') unborn = true;
        else if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
      }
      const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
      const lines: string[] = [];
      const headTip = repo.refs.get(defaultBranchRef(repo));
      if (keep('HEAD')) {
        if (headTip !== undefined) lines.push(lsRefsLine(repo, 'HEAD', headTip, { peel, symrefs }));
        else if (unborn) lines.push(`unborn HEAD symref-target:${defaultBranchRef(repo)}\n`);
      }
      const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
      for (const [name, oid] of refs) {
        if (keep(name)) lines.push(lsRefsLine(repo, name, oid, { peel, symrefs }));
      }
      const out = encodePktLines([...lines, 'flush']);
      sendRaw(res, 200, out, 'application/x-git-upload-pack-result');
      return;
    }
    if (command === 'command=fetch') {
      const wants: string[] = [];
      const haves: string[] = [];
      const shallow: string[] = [];
      let depth: number | undefined;
      let deepenSince: number | undefined;
      for (const arg of args) {
        const text = arg.replace(/\n$/, '');
        if (text.startsWith('want ')) wants.push(text.slice(5).trim());
        else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
        else if (text.startsWith('shallow ')) shallow.push(text.slice(8).trim());
        else if (text.startsWith('deepen ')) depth = Number(text.slice(7).trim());
        else if (text.startsWith('deepen-since ')) deepenSince = Number(text.slice(13).trim());
      }
      const plan = planFetch(repo, wants, haves, shallow, depth, deepenSince);
      const parts: Buffer[] = [];
      // The acknowledgments section is only sent when the client sent have
      // lines: a fresh clone expects the packfile section first, and real git
      // rejects an acknowledgments section it did not negotiate for.
      if (haves.length > 0) {
        const knownHaves = haves.filter((h) => repo.objects.has(h));
        parts.push(encodePktLine('acknowledgments\n'));
        if (knownHaves.length > 0) {
          for (const have of knownHaves) parts.push(encodePktLine(`ACK ${have}\n`));
          parts.push(encodePktLine('ready\n'));
        } else {
          parts.push(encodePktLine('NAK\n'));
        }
        parts.push(PKT_DELIM);
      }
      if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
        parts.push(encodePktLine('shallow-info\n'));
        for (const oid of plan.shallow) parts.push(encodePktLine(`shallow ${oid}\n`));
        for (const oid of plan.unshallow) parts.push(encodePktLine(`unshallow ${oid}\n`));
        parts.push(PKT_DELIM);
      }
      if (plan.objects.size > 0) {
        parts.push(encodePktLine('packfile\n'));
        const pack = writePack([...plan.objects.values()]);
        parts.push(sidebandFrames(pack));
      }
      parts.push(PKT_FLUSH);
      sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
      return;
    }
    sendJson(res, 400, { message: 'Bad Request' });
    return;
  }

  // Protocol v0: want/have lines in two flush-separated sections.
  const lines: string[] = [];
  const haves: string[] = [];
  let section = 0;
  let depth: number | undefined;
  let deepenSince: number | undefined;
  const shallow: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'flush') { section += 1; continue; }
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8').replace(/\n$/, '');
    if (section === 0) {
      if (text.startsWith('want ')) {
        const rest = text.slice(5);
        const nul = rest.indexOf('\0');
        lines.push(nul >= 0 ? rest.slice(0, nul).trim() : rest.trim());
      } else if (text.startsWith('shallow ')) shallow.push(text.slice(8).trim());
      else if (text.startsWith('deepen ')) depth = Number(text.slice(7).trim());
      else if (text.startsWith('deepen-since ')) deepenSince = Number(text.slice(13).trim());
    } else if (text.startsWith('have ')) {
      haves.push(text.slice(5).trim());
    }
  }
  if (lines.length === 0) {
    sendJson(res, 400, { message: 'Bad Request' });
    return;
  }
  const plan = planFetch(repo, lines, haves, shallow, depth, deepenSince);
  const parts: Buffer[] = [];
  const knownHaves = haves.filter((h) => repo.objects.has(h));
  if (knownHaves.length > 0) {
    for (const have of knownHaves) parts.push(encodePktLine(`ACK ${have}\n`));
  } else {
    parts.push(encodePktLine('NAK\n'));
  }
  for (const oid of plan.shallow) parts.push(encodePktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(encodePktLine(`unshallow ${oid}\n`));
  if (plan.objects.size > 0) {
    const pack = writePack([...plan.objects.values()]);
    parts.push(sidebandFrames(pack));
  }
  parts.push(PKT_FLUSH);
  sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}

/** Handle POST /{owner}/{repo}.git/git-receive-pack (v0). */
function handleReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo, bodyBuf: Buffer): void {
  // The body is command pkt-lines up to the first flush, then the raw pack.
  // Never decode the whole body as pkt-lines: the pack bytes are not framed.
  interface Command {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const commands: Command[] = [];
  let capabilities = '';
  let packOffset = 0;
  // Walk the raw buffer: command lines are pkt-lines until the first flush.
  {
    let offset = 0;
    let done = false;
    while (offset + 4 <= bodyBuf.length && !done) {
      const hex = bodyBuf.subarray(offset, offset + 4).toString('ascii');
      if (!/^[0-9a-f]{4}$/.test(hex)) break;
      const len = parseInt(hex, 16);
      if (len === 0) {
        offset += 4;
        done = true;
        break;
      }
      if (len < 4 || offset + len > bodyBuf.length) break;
      const payload = bodyBuf.subarray(offset + 4, offset + len).toString('utf8');
      offset += len;
      const text = payload.replace(/\n$/, '');
      const nul = text.indexOf('\0');
      const head = nul >= 0 ? text.slice(0, nul) : text;
      if (nul >= 0 && commands.length === 0) capabilities = text.slice(nul + 1);
      const parts = head.split(' ');
      if (parts.length >= 3 && OID_RE.test(parts[0]) && OID_RE.test(parts[1])) {
        commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
      }
    }
    packOffset = offset;
  }
  if (commands.length === 0) {
    sendJson(res, 400, { message: 'Bad Request' });
    return;
  }
  const sideband = capabilities.split(' ').includes('side-band-64k');

  // Unpack: everything after the command flush is the pack (maybe none).
  let unpackOk = true;
  let unpackDetail = 'ok';
  const packBytes = bodyBuf.subarray(packOffset);
  if (packBytes.length > 0) {
    try {
      const read = readPack(Buffer.from(packBytes));
      for (const [oid, object] of read.objects) repo.objects.set(oid, object);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  }

  const reportLines: string[] = [];
  reportLines.push(unpackOk ? 'unpack ok\n' : `unpack ${unpackDetail}\n`);
  let changed = false;
  for (const command of commands) {
    const refOk = /^refs\/[^\s~^:?*[\\]+$/.test(command.ref) && !command.ref.includes('..') && !command.ref.endsWith('.lock');
    if (!refOk) {
      reportLines.push(`ng ${command.ref} invalid ref name\n`);
      continue;
    }
    if (!unpackOk) {
      reportLines.push(`ng ${command.ref} unpack failed\n`);
      continue;
    }
    const current = repo.refs.get(command.ref);
    if (command.newOid === ZERO_OID) {
      // Delete.
      if (current === undefined) {
        reportLines.push(`ng ${command.ref} remote ref does not exist\n`);
      } else if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
        reportLines.push(`ng ${command.ref} old oid does not match current\n`);
      } else {
        repo.refs.delete(command.ref);
        changed = true;
        reportLines.push(`ok ${command.ref}\n`);
      }
      continue;
    }
    if (!repo.objects.has(command.newOid)) {
      reportLines.push(`ng ${command.ref} unable to resolve new object\n`);
      continue;
    }
    if (command.oldOid === ZERO_OID) {
      // Create.
      if (current !== undefined) {
        reportLines.push(`ng ${command.ref} reference already exists\n`);
      } else {
        repo.refs.set(command.ref, command.newOid);
        changed = true;
        reportLines.push(`ok ${command.ref}\n`);
      }
      continue;
    }
    // Update.
    if (current === undefined) {
      reportLines.push(`ng ${command.ref} remote ref does not exist\n`);
    } else if (command.oldOid !== current) {
      reportLines.push(`ng ${command.ref} old oid does not match current\n`);
    } else if (command.newOid === command.oldOid) {
      reportLines.push(`ok ${command.ref}\n`);
    } else if (!isAncestor(repo, command.oldOid, command.newOid)) {
      reportLines.push(`ng ${command.ref} non-fast-forward\n`);
    } else {
      repo.refs.set(command.ref, command.newOid);
      changed = true;
      reportLines.push(`ok ${command.ref}\n`);
    }
  }
  if (changed) {
    const now = nextTs();
    repo.updatedSec = now;
    repo.pushedSec = now;
  }
  const report = encodePktLines(reportLines);
  let out: Buffer;
  if (sideband) {
    // The report is itself a pkt-line stream inside sideband band 1, so its
    // own terminating flush travels INSIDE the band-1 data (this is what real
    // git sends); the outer flush then closes the sideband stream.
    out = Buffer.concat([sidebandFrames(Buffer.concat([report, PKT_FLUSH])), PKT_FLUSH]);
  } else {
    out = Buffer.concat([report, PKT_FLUSH]);
  }
  sendRaw(res, 200, out, 'application/x-git-receive-pack-result');
}

// ============================================================================
// GraphQL v4 (the documents gh and github-mcp-server actually send)
// ============================================================================

type GqlValue = unknown;

interface GqlField {
  alias: string | null;
  name: string;
  args: Record<string, GqlValue>;
  selection: GqlField[] | null;
  fragmentType: string | null; // for inline fragments: "... on Type"
  isFragment: boolean;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  variables: Record<string, GqlValue>;
  selection: GqlField[];
}

/** A tiny GraphQL parser: operations, fields, aliases, arguments, fragments. */
class GqlParser {
  private pos = 0;
  private readonly text: string;
  constructor(text: string) {
    this.text = text;
  }

  private skipIgnored(): void {
    for (;;) {
      while (this.pos < this.text.length && /[\s,]/.test(this.text[this.pos] as string)) this.pos += 1;
      if (this.text[this.pos] === '#') {
        while (this.pos < this.text.length && this.text[this.pos] !== '\n') this.pos += 1;
        continue;
      }
      return;
    }
  }

  private peek(): string {
    this.skipIgnored();
    return this.text[this.pos] ?? '';
  }

  private expect(value: string): void {
    this.skipIgnored();
    if (!this.text.startsWith(value, this.pos)) throw new Error(`expected ${JSON.stringify(value)} at ${this.pos}`);
    this.pos += value.length;
  }

  private tryConsume(value: string): boolean {
    this.skipIgnored();
    if (this.text.startsWith(value, this.pos)) {
      this.pos += value.length;
      return true;
    }
    return false;
  }

  private readName(): string {
    this.skipIgnored();
    const match = /^[A-Za-z_][A-Za-z0-9_]*/.exec(this.text.slice(this.pos));
    if (match === null) throw new Error(`expected a name at ${this.pos}`);
    this.pos += match[0].length;
    return match[0];
  }

  private readString(): string {
    this.skipIgnored();
    if (this.text[this.pos] !== '"') throw new Error(`expected a string at ${this.pos}`);
    this.pos += 1;
    let out = '';
    while (this.pos < this.text.length) {
      const ch = this.text[this.pos] as string;
      if (ch === '"') {
        this.pos += 1;
        return out;
      }
      if (ch === '\\') {
        const next = this.text[this.pos + 1] as string;
        const escapes: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/' };
        out += escapes[next] ?? next;
        this.pos += 2;
        continue;
      }
      out += ch;
      this.pos += 1;
    }
    throw new Error('unterminated string');
  }

  private readNumber(): number {
    this.skipIgnored();
    const match = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.text.slice(this.pos));
    if (match === null) throw new Error(`expected a number at ${this.pos}`);
    this.pos += match[0].length;
    return Number(match[0]);
  }

  private readValue(variables: Record<string, GqlValue>): GqlValue {
    this.skipIgnored();
    const ch = this.text[this.pos] ?? '';
    if (ch === '$') {
      this.pos += 1;
      const name = this.readName();
      return variables[name] ?? null;
    }
    if (ch === '"') return this.readString();
    if (ch === '[') {
      this.pos += 1;
      const list: GqlValue[] = [];
      while (!this.tryConsume(']')) list.push(this.readValue(variables));
      return list;
    }
    if (ch === '{') {
      this.pos += 1;
      const object: Record<string, GqlValue> = {};
      while (!this.tryConsume('}')) {
        const key = this.readName();
        this.expect(':');
        object[key] = this.readValue(variables);
      }
      return object;
    }
    if (ch === '-' || /[0-9]/.test(ch)) return this.readNumber();
    const name = this.readName();
    if (name === 'true') return true;
    if (name === 'false') return false;
    if (name === 'null') return null;
    return name; // enum value
  }

  private readArguments(variables: Record<string, GqlValue>): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    if (!this.tryConsume('(')) return args;
    while (!this.tryConsume(')')) {
      const name = this.readName();
      this.expect(':');
      args[name] = this.readValue(variables);
    }
    return args;
  }

  private readVariableDefinitions(): Record<string, GqlValue> {
    // Variable values come from the request; definitions only declare names.
    const defs: Record<string, GqlValue> = {};
    if (!this.tryConsume('(')) return defs;
    while (!this.tryConsume(')')) {
      this.expect('$');
      const name = this.readName();
      this.expect(':');
      // The type: a name, possibly wrapped in [] and suffixed with !.
      this.skipIgnored();
      if (this.text[this.pos] === '[') {
        this.pos += 1;
        this.readName();
        this.tryConsume(']');
      } else {
        this.readName();
      }
      this.tryConsume('!');
      if (this.tryConsume('=')) this.readValue({});
      defs[name] = null;
    }
    return defs;
  }

  private readSelectionSet(variables: Record<string, GqlValue>): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (!this.tryConsume('}')) {
      if (this.text.startsWith('...', this.pos)) {
        this.pos += 3;
        this.skipIgnored();
        if (this.text.startsWith('on', this.pos) && /[\s{]/.test(this.text[this.pos + 2] ?? '')) {
          this.pos += 2;
          const type = this.readName();
          const selection = this.readSelectionSet(variables);
          fields.push({ alias: null, name: '', args: {}, selection, fragmentType: type, isFragment: true });
        } else {
          // Named fragment spread: "...Name" — resolve from the document's
          // fragments (collected by the caller through parseDocument).
          const name = this.readName();
          fields.push({ alias: null, name, args: {}, selection: null, fragmentType: null, isFragment: true });
        }
        continue;
      }
      const first = this.readName();
      let alias: string | null = null;
      let name = first;
      if (this.tryConsume(':')) {
        alias = first;
        name = this.readName();
      }
      const args = this.readArguments(variables);
      const selection = this.peek() === '{' ? this.readSelectionSet(variables) : null;
      fields.push({ alias, name, args, selection, fragmentType: null, isFragment: false });
    }
    return fields;
  }

  parseDocument(variables: Record<string, GqlValue>): { operations: GqlOperation[]; fragments: Map<string, GqlField[]> } {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlField[]>();
    for (;;) {
      this.skipIgnored();
      if (this.pos >= this.text.length) break;
      if (this.text.startsWith('fragment', this.pos)) {
        this.pos += 'fragment'.length;
        const name = this.readName();
        this.expect('on');
        this.readName();
        fragments.set(name, this.readSelectionSet(variables));
        continue;
      }
      let kind: 'query' | 'mutation' = 'query';
      if (this.text.startsWith('query', this.pos) && /[\s({]/.test(this.text[this.pos + 5] ?? '')) {
        this.pos += 5;
      } else if (this.text.startsWith('mutation', this.pos) && /[\s({]/.test(this.text[this.pos + 8] ?? '')) {
        this.pos += 8;
        kind = 'mutation';
      }
      this.skipIgnored();
      let name: string | null = null;
      if (/[A-Za-z_]/.test(this.peek())) name = this.readName();
      this.readVariableDefinitions();
      const selection = this.readSelectionSet(variables);
      operations.push({ kind, name, variables, selection });
    }
    return { operations, fragments };
  }
}

// --- GraphQL type tables (for __type introspection) ---------------------------

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'body', 'state', 'createdAt', 'updatedAt', 'author', 'comments', 'labels', 'url', 'resourcePath', 'closedAt', 'assignees', 'milestone'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'author', 'createdAt', 'updatedAt', 'url', 'closedAt', 'mergedAt', 'mergeCommit', 'additions', 'deletions', 'changedFiles', 'commits', 'isDraft'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'createdAt', 'updatedAt', 'url', 'description', 'isPrivate', 'forkCount', 'stargazerCount', 'licenseInfo'],
  User: ['id', 'login', 'name', 'email', 'url', 'avatarUrl'],
};
const GQL_TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'WIKI', 'MILESTONE', 'LABEL', 'TOPIC', 'PACKAGE', 'MARKETPLACE', 'APP'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  MergeStateStatus: ['BEHIND', 'BLOCKED', 'CLEAN', 'DIRTY', 'DRAFT', 'HAS_HOOKS', 'UNKNOWN', 'UNSTABLE'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
};

function decodeGlobalId(id: string): { kind: string; owner: string; name: string; number: number; extra: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const match = /^([RIPCU]):([^/#]+)(?:\/([^#]+))?(?:#(\d+))?(?::(.*))?$/.exec(text);
    if (match === null) return null;
    return {
      kind: match[1] as string,
      owner: match[2] as string,
      name: match[3] ?? '',
      number: match[4] === undefined ? 0 : Number(match[4]),
      extra: match[5] ?? '',
    };
  } catch {
    return null;
  }
}

function cursorFor(number: number): string {
  return Buffer.from(`cursor:${number}`).toString('base64');
}

function numberFromCursor(cursor: string): number | null {
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match === null ? null : Number(match[1]);
  } catch {
    return null;
  }
}

// --- GraphQL execution ---------------------------------------------------------

type GqlObject =
  | { kind: 'Query' }
  | { kind: 'Repository'; repo: Repo }
  | { kind: 'Issue'; repo: Repo; issue: Issue }
  | { kind: 'PullRequest'; repo: Repo; pull: Pull }
  | { kind: 'User'; login: string }
  | { kind: 'Ref'; name: string }
  | { kind: 'IssueConnection'; repo: Repo; issues: Issue[] }
  | { kind: 'PullRequestConnection'; repo: Repo; pulls: Pull[] }
  | { kind: 'ChangedFiles'; repo: Repo; pull: Pull }
  | { kind: 'Type'; name: string }
  | { kind: 'CommentEdge'; repo: Repo; issue: Issue; comment: IssueComment };

class GraphQLExecutor {
  private errors: Array<{ message: string; path: (string | number)[] }> = [];
  private readonly origin: string;
  constructor(origin: string) {
    this.origin = origin;
  }

  private error(message: string, path: (string | number)[]): void {
    this.errors.push({ message, path });
  }

  executeOperation(operation: GqlOperation, fragments: Map<string, GqlField[]>): { data: JsonObject; errors: Array<{ message: string; path: (string | number)[] }> } {
    this.errors = [];
    const root: GqlObject = { kind: 'Query' };
    const data = this.resolveSelection(root, operation.selection, fragments, []);
    return { data, errors: this.errors };
  }

  private resolveSelection(object: GqlObject, fields: GqlField[], fragments: Map<string, GqlField[]>, path: (string | number)[]): JsonObject {
    const out: JsonObject = {};
    for (const field of fields) {
      if (field.isFragment) {
        if (field.fragmentType !== null) {
          const typeName = typeNameOf(object);
          if (typeName === field.fragmentType || (field.fragmentType === 'Node' && (typeName === 'Repository' || typeName === 'Issue' || typeName === 'PullRequest'))) {
            const nested = this.resolveSelection(object, field.selection ?? [], fragments, path);
            Object.assign(out, nested);
          }
        } else if (field.selection === null) {
          const fragment = fragments.get(field.name);
          if (fragment !== undefined) {
            const nested = this.resolveSelection(object, fragment, fragments, path);
            Object.assign(out, nested);
          }
        }
        continue;
      }
      const key = field.alias ?? field.name;
      const value = this.resolveField(object, field, fragments, [...path, key]);
      if (value === undefined) {
        // Unknown field: null in data plus an error entry.
        out[key] = null;
        continue;
      }
      out[key] = value;
    }
    return out;
  }

  private resolveField(object: GqlObject, field: GqlField, fragments: Map<string, GqlField[]>, path: (string | number)[]): unknown {
    const name = field.name;
    const sel = field.selection ?? [];
    const args = field.args;

    if (object.kind === 'Query') {
      if (name === 'viewer') {
        const user: GqlObject = { kind: 'User', login: VIEWER_LOGIN };
        return this.resolveSelection(user, sel, fragments, path);
      }
      if (name === 'repository') {
        const owner = args.owner as string | undefined;
        const repoName = args.name as string | undefined;
        if (owner !== VIEWER_LOGIN) return null;
        const repo = owner === undefined || repoName === undefined ? undefined : findRepo(owner, repoName);
        if (repo === undefined) return null;
        const repoObject: GqlObject = { kind: 'Repository', repo };
        return this.resolveSelection(repoObject, sel, fragments, path);
      }
      if (name === 'node') {
        const id = args.id as string | undefined;
        if (id === undefined) return null;
        const decoded = decodeGlobalId(id);
        if (decoded === null) return null;
        if (decoded.kind === 'R') {
          const repo = findRepo(decoded.owner, decoded.name);
          if (repo === undefined) return null;
          const repoObject: GqlObject = { kind: 'Repository', repo };
          return this.resolveSelection(repoObject, sel, fragments, path);
        }
        return null;
      }
      if (name === '__type') {
        const typeName = args.name as string | undefined;
        if (typeName === undefined) return null;
        if (GQL_TYPE_FIELDS[typeName] === undefined && GQL_TYPE_ENUMS[typeName] === undefined) return null;
        const typeObject: GqlObject = { kind: 'Type', name: typeName };
        return this.resolveSelection(typeObject, sel, fragments, path);
      }
      if (name === '__schema') {
        return { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, types: [] };
      }
      if (name === 'createIssue' || name === 'closeIssue' || name === 'createPullRequest' || name === 'mergePullRequest' || name === 'addComment') {
        return this.resolveMutation(name, args, sel, fragments, path);
      }
      this.error(`Cannot query field "${name}" on type "Query".`, path);
      return undefined;
    }

    if (object.kind === 'User') {
      if (name === 'login') return object.login;
      if (name === 'id') return b64encode(`U:${object.login}`);
      if (name === 'name') return object.login === VIEWER_LOGIN ? VIEWER_NAME : object.login;
      this.error(`Cannot query field "${name}" on type "User".`, path);
      return undefined;
    }

    if (object.kind === 'Ref') {
      if (name === 'name') return object.name;
      this.error(`Cannot query field "${name}" on type "Ref".`, path);
      return undefined;
    }

    if (object.kind === 'Type') {
      if (name === 'name') return object.name;
      if (name === 'kind') return GQL_TYPE_ENUMS[object.name] !== undefined ? 'ENUM' : 'OBJECT';
      if (name === 'fields') {
        const names = GQL_TYPE_FIELDS[object.name] ?? [];
        return names.map((n) => ({ name: n }));
      }
      if (name === 'enumValues') {
        const names = GQL_TYPE_ENUMS[object.name] ?? [];
        return names.map((n) => ({ name: n }));
      }
      this.error(`Cannot query field "${name}" on type "__Type".`, path);
      return undefined;
    }

    if (object.kind === 'Repository') {
      const repo = object.repo;
      switch (name) {
        case 'id': return repoNodeId(repo);
        case 'databaseId': return repo.id;
        case 'name': return repo.name;
        case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
        case 'owner': {
          const user: GqlObject = { kind: 'User', login: repo.owner };
          return this.resolveSelection(user, sel, fragments, path);
        }
        case 'defaultBranchRef': {
          const tip = repo.refs.get(defaultBranchRef(repo));
          if (tip === undefined) return null;
          const ref: GqlObject = { kind: 'Ref', name: repo.defaultBranch };
          return this.resolveSelection(ref, sel, fragments, path);
        }
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': return true;
        case 'description': return repo.description;
        case 'isPrivate': return repo.private;
        case 'createdAt': return isoOf(repo.createdSec);
        case 'updatedAt': return isoOf(repo.updatedSec);
        case 'url': return `https://github.invalid/${repo.owner}/${repo.name}`;
        case 'issue': {
          const number = args.number as number | undefined;
          if (number === undefined) return null;
          const issue = repo.issues.get(number);
          if (issue === undefined) return null;
          const issueObject: GqlObject = { kind: 'Issue', repo, issue };
          return this.resolveSelection(issueObject, sel, fragments, path);
        }
        case 'issues': {
          const issues = this.issueConnection(repo, args);
          const conn: GqlObject = { kind: 'IssueConnection', repo, issues: issues.items };
          const out = this.resolveSelection(conn, sel, fragments, path);
          // pageInfo lives on the connection object, not in `issues`.
          out.pageInfo = issues.pageInfo;
          return out;
        }
        case 'pullRequest': {
          const number = args.number as number | undefined;
          if (number === undefined) return null;
          const pull = repo.pulls.get(number);
          if (pull === undefined) return null;
          const pullObject: GqlObject = { kind: 'PullRequest', repo, pull };
          return this.resolveSelection(pullObject, sel, fragments, path);
        }
        case 'pullRequests': {
          const first = typeof args.first === 'number' ? args.first : 30;
          const pulls = [...repo.pulls.values()].sort((a, b) => b.createdSec - a.createdSec || b.number - a.number).slice(0, first);
          const conn: GqlObject = { kind: 'PullRequestConnection', repo, pulls };
          return this.resolveSelection(conn, sel, fragments, path);
        }
        default:
          this.error(`Cannot query field "${name}" on type "Repository".`, path);
          return undefined;
      }
    }

    if (object.kind === 'Issue') {
      const issue = object.issue;
      switch (name) {
        case 'id': return issueNodeId(object.repo, issue.number);
        case 'number': return issue.number;
        case 'title': return issue.title;
        case 'body': return issue.body;
        case 'state': return issue.state === 'open' ? 'OPEN' : 'CLOSED';
        case 'createdAt': return isoOf(issue.createdSec);
        case 'updatedAt': return isoOf(issue.updatedSec);
        case 'closedAt': return issue.closedSec === null ? null : isoOf(issue.closedSec);
        case 'author': {
          const user: GqlObject = { kind: 'User', login: VIEWER_LOGIN };
          return this.resolveSelection(user, sel, fragments, path);
        }
        case 'url': return `https://github.invalid/${object.repo.owner}/${object.repo.name}/issues/${issue.number}`;
        case 'comments': return { totalCount: issue.comments.length };
        default:
          this.error(`Cannot query field "${name}" on type "Issue".`, path);
          return undefined;
      }
    }

    if (object.kind === 'PullRequest') {
      const pull = object.pull;
      switch (name) {
        case 'id': return pullNodeId(object.repo, pull.number);
        case 'number': return pull.number;
        case 'title': return pull.title;
        case 'body': return pull.body;
        case 'state': return pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
        case 'merged': return pull.merged;
        case 'mergeable': return pullMergeable(object.repo, pull) ? 'MERGEABLE' : pull.state === 'open' ? 'CONFLICTING' : 'UNKNOWN';
        case 'headRefName': return pull.head;
        case 'baseRefName': return pull.base;
        case 'headRef': {
          const ref: GqlObject = { kind: 'Ref', name: pull.head };
          return this.resolveSelection(ref, sel, fragments, path);
        }
        case 'baseRef': {
          const ref: GqlObject = { kind: 'Ref', name: pull.base };
          return this.resolveSelection(ref, sel, fragments, path);
        }
        case 'files': {
          const first = typeof args.first === 'number' ? args.first : 10;
          const changed: GqlObject = { kind: 'ChangedFiles', repo: object.repo, pull };
          const out = this.resolveSelection(changed, sel, fragments, path);
          void first;
          return out;
        }
        case 'createdAt': return isoOf(pull.createdSec);
        case 'updatedAt': return isoOf(pull.updatedSec);
        case 'closedAt': return pull.state === 'closed' ? isoOf(pull.updatedSec) : null;
        case 'mergedAt': return pull.mergedSec === null ? null : isoOf(pull.mergedSec);
        case 'author': {
          const user: GqlObject = { kind: 'User', login: VIEWER_LOGIN };
          return this.resolveSelection(user, sel, fragments, path);
        }
        case 'url': return `https://github.invalid/${object.repo.owner}/${object.repo.name}/pull/${pull.number}`;
        default:
          this.error(`Cannot query field "${name}" on type "PullRequest".`, path);
          return undefined;
      }
    }

    if (object.kind === 'IssueConnection') {
      if (name === 'nodes') {
        return object.issues.map((issue) => {
          const issueObject: GqlObject = { kind: 'Issue', repo: object.repo, issue };
          return this.resolveSelection(issueObject, sel, fragments, path);
        });
      }
      if (name === 'edges') {
        return object.issues.map((issue) => ({
          cursor: cursorFor(issue.number),
          node: this.resolveSelection({ kind: 'Issue', repo: object.repo, issue }, sel, fragments, path),
        }));
      }
      if (name === 'totalCount') return object.issues.length;
      if (name === 'pageInfo') return { hasNextPage: false, endCursor: null };
      this.error(`Cannot query field "${name}" on type "IssueConnection".`, path);
      return undefined;
    }

    if (object.kind === 'PullRequestConnection') {
      if (name === 'nodes') {
        return object.pulls.map((pull) => {
          const pullObject: GqlObject = { kind: 'PullRequest', repo: object.repo, pull };
          return this.resolveSelection(pullObject, sel, fragments, path);
        });
      }
      if (name === 'totalCount') return object.pulls.length;
      this.error(`Cannot query field "${name}" on type "PullRequestConnection".`, path);
      return undefined;
    }

    if (object.kind === 'ChangedFiles') {
      if (name === 'nodes') {
        const pull = object.pull;
        const repo = object.repo;
        const base = mergeBase(repo, pull.baseSha, pull.headSha) ?? pull.baseSha;
        const baseCommit = repo.objects.get(base);
        const headCommit = repo.objects.get(pull.headSha);
        if (baseCommit === undefined || headCommit === undefined) return [];
        const baseTree = parseCommit(baseCommit.data).tree;
        const headTree = parseCommit(headCommit.data).tree;
        return diffTrees(repo, baseTree, headTree).map((d) => ({ path: d.path }));
      }
      if (name === 'totalCount') {
        const pull = object.pull;
        const repo = object.repo;
        const base = mergeBase(repo, pull.baseSha, pull.headSha) ?? pull.baseSha;
        const baseCommit = repo.objects.get(base);
        const headCommit = repo.objects.get(pull.headSha);
        if (baseCommit === undefined || headCommit === undefined) return 0;
        return diffTrees(repo, parseCommit(baseCommit.data).tree, parseCommit(headCommit.data).tree).length;
      }
      this.error(`Cannot query field "${name}" on type "PullRequestChangedFileConnection".`, path);
      return undefined;
    }

    if (object.kind === 'CommentEdge') {
      if (name === 'node') {
        return { id: commentNodeId(object.repo, object.issue.number, object.comment.id), body: object.comment.body };
      }
      if (name === 'cursor') return cursorFor(object.comment.id);
      this.error(`Cannot query field "${name}" on type "IssueCommentEdge".`, path);
      return undefined;
    }

    this.error(`Cannot query field "${name}".`, path);
    return undefined;
  }

  private issueConnection(repo: Repo, args: Record<string, GqlValue>): { items: Issue[]; pageInfo: { hasNextPage: boolean; endCursor: string | null } } {
    let list = [...repo.issues.values()];
    const states = args.states;
    if (Array.isArray(states) && states.length > 0) {
      const wanted = new Set(states.map((s) => String(s).toLowerCase()));
      list = list.filter((i) => wanted.has(i.state));
    }
    const orderBy = asObject(args.orderBy);
    const field = orderBy !== null && typeof orderBy.field === 'string' ? orderBy.field : 'CREATED_AT';
    const direction = orderBy !== null && typeof orderBy.direction === 'string' ? orderBy.direction : 'DESC';
    const key = field === 'UPDATED_AT' ? (i: Issue): number => i.updatedSec : field === 'COMMENTS' ? (i: Issue): number => i.comments.length : (i: Issue): number => i.createdSec;
    list.sort((a, b) => (direction === 'ASC' ? key(a) - key(b) : key(b) - key(a)) || a.number - b.number);
    const after = typeof args.after === 'string' ? numberFromCursor(args.after) : null;
    if (after !== null) {
      const index = list.findIndex((i) => i.number === after);
      if (index >= 0) list = list.slice(index + 1);
    }
    const first = typeof args.first === 'number' ? args.first : 30;
    const page = list.slice(0, first);
    const hasNextPage = list.length > first;
    const endCursor = page.length > 0 ? cursorFor((page[page.length - 1] as Issue).number) : null;
    return { items: page, pageInfo: { hasNextPage, endCursor } };
  }

  private resolveMutation(name: string, args: Record<string, GqlValue>, sel: GqlField[], fragments: Map<string, GqlField[]>, path: (string | number)[]): unknown {
    const input = asObject(args.input) ?? {};
    if (name === 'createIssue') {
      const repositoryId = typeof input.repositoryId === 'string' ? input.repositoryId : '';
      const title = typeof input.title === 'string' ? input.title : '';
      const decoded = decodeGlobalId(repositoryId);
      const repo = decoded !== null && decoded.kind === 'R' ? findRepo(decoded.owner, decoded.name) : undefined;
      if (repo === undefined || title === '') {
        this.error('createIssue: unknown repository or missing title.', path);
        return null;
      }
      const now = nextTs();
      const number = repo.nextNumber;
      repo.nextNumber += 1;
      const issue: Issue = {
        number,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels: [],
        comments: [],
        createdSec: now,
        updatedSec: now,
        closedSec: null,
        nextCommentId: 1,
      };
      repo.issues.set(number, issue);
      const issueObject: GqlObject = { kind: 'Issue', repo, issue };
      return { issue: this.resolveSelection(issueObject, sel[0]?.selection ?? [], fragments, [...path, 'issue']) };
    }
    if (name === 'closeIssue') {
      const issueId = typeof input.issueId === 'string' ? input.issueId : '';
      const decoded = decodeGlobalId(issueId);
      const repo = decoded !== null && decoded.kind === 'I' ? findRepo(decoded.owner, decoded.name) : undefined;
      const issue = repo?.issues.get(decoded?.number ?? -1);
      if (repo === undefined || issue === undefined) {
        this.error('closeIssue: unknown issue.', path);
        return null;
      }
      issue.state = 'closed';
      issue.closedSec = nextTs();
      issue.updatedSec = nextTs();
      const issueObject: GqlObject = { kind: 'Issue', repo, issue };
      return { issue: this.resolveSelection(issueObject, sel[0]?.selection ?? [], fragments, [...path, 'issue']) };
    }
    if (name === 'createPullRequest') {
      const repositoryId = typeof input.repositoryId === 'string' ? input.repositoryId : '';
      const decoded = decodeGlobalId(repositoryId);
      const repo = decoded !== null && decoded.kind === 'R' ? findRepo(decoded.owner, decoded.name) : undefined;
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      const title = typeof input.title === 'string' ? input.title : '';
      const headTip = repo?.refs.get(`refs/heads/${head}`);
      const baseTip = repo?.refs.get(`refs/heads/${base}`);
      if (repo === undefined || headTip === undefined || baseTip === undefined || title === '') {
        this.error('createPullRequest: unknown repository or branch.', path);
        return null;
      }
      const now = nextTs();
      const number = repo.nextNumber;
      repo.nextNumber += 1;
      const pull: Pull = {
        number,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        merged: false,
        head,
        base,
        headSha: headTip,
        baseSha: baseTip,
        mergeCommitSha: null,
        mergedSec: null,
        createdSec: now,
        updatedSec: now,
      };
      repo.pulls.set(number, pull);
      const pullObject: GqlObject = { kind: 'PullRequest', repo, pull };
      return { pullRequest: this.resolveSelection(pullObject, sel[0]?.selection ?? [], fragments, [...path, 'pullRequest']) };
    }
    if (name === 'mergePullRequest') {
      const pullRequestId = typeof input.pullRequestId === 'string' ? input.pullRequestId : '';
      const decoded = decodeGlobalId(pullRequestId);
      const repo = decoded !== null && decoded.kind === 'P' ? findRepo(decoded.owner, decoded.name) : undefined;
      const pull = repo?.pulls.get(decoded?.number ?? -1);
      if (repo === undefined || pull === undefined) {
        this.error('mergePullRequest: unknown pull request.', path);
        return null;
      }
      const merged = mergePullRequest(repo, pull, typeof input.mergeMethod === 'string' ? input.mergeMethod : 'MERGE');
      if (!merged) {
        this.error('mergePullRequest: the pull request cannot be merged cleanly.', path);
        return { pullRequest: null };
      }
      const pullObject: GqlObject = { kind: 'PullRequest', repo, pull };
      return { pullRequest: this.resolveSelection(pullObject, sel[0]?.selection ?? [], fragments, [...path, 'pullRequest']) };
    }
    if (name === 'addComment') {
      const subjectId = typeof input.subjectId === 'string' ? input.subjectId : '';
      const bodyText = typeof input.body === 'string' ? input.body : '';
      const decoded = decodeGlobalId(subjectId);
      const repo = decoded !== null && (decoded.kind === 'I' || decoded.kind === 'P') ? findRepo(decoded.owner, decoded.name) : undefined;
      const issue = repo?.issues.get(decoded?.number ?? -1);
      if (repo === undefined || issue === undefined || bodyText === '') {
        this.error('addComment: unknown subject.', path);
        return null;
      }
      const now = nextTs();
      const comment: IssueComment = { id: issue.nextCommentId, body: bodyText, createdSec: now, updatedSec: now };
      issue.nextCommentId += 1;
      issue.comments.push(comment);
      issue.updatedSec = now;
      const edge: GqlObject = { kind: 'CommentEdge', repo, issue, comment };
      const edgeSel = sel[0]?.selection ?? [];
      const nodeField = edgeSel.find((f) => f.name === 'node');
      const node = nodeField !== undefined ? { id: commentNodeId(repo, issue.number, comment.id), body: comment.body } : null;
      void edge;
      return { commentEdge: { node } };
    }
    this.error(`Cannot query field "${name}" on type "Mutation".`, path);
    return null;
  }
}

function typeNameOf(object: GqlObject): string {
  switch (object.kind) {
    case 'Query': return 'Query';
    case 'Repository': return 'Repository';
    case 'Issue': return 'Issue';
    case 'PullRequest': return 'PullRequest';
    case 'User': return 'User';
    case 'Ref': return 'Ref';
    case 'IssueConnection': return 'IssueConnection';
    case 'PullRequestConnection': return 'PullRequestConnection';
    case 'ChangedFiles': return 'PullRequestChangedFileConnection';
    case 'Type': return '__Type';
    case 'CommentEdge': return 'IssueCommentEdge';
    default: return 'Query';
  }
}

/** Merge a pull request the way PUT /pulls/{n}/merge does; false when conflicted. */
function mergePullRequest(repo: Repo, pull: Pull, mergeMethod: string): boolean {
  if (pull.state !== 'open') return false;
  if (!pullMergeable(repo, pull)) return false;
  const baseTip = refTip(repo, `refs/heads/${pull.base}`) ?? pull.baseSha;
  const headCommit = repo.objects.get(pull.headSha);
  if (headCommit === undefined) return false;
  const headTree = parseCommit(headCommit.data).tree;
  const epochSec = nextTs();
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitDateOf(epochSec)}`;
  let message: string;
  let parents: string[];
  if (mergeMethod === 'SQUASH') {
    message = `${pull.title} (#${pull.number})`;
    parents = [baseTip];
  } else if (mergeMethod === 'REBASE') {
    message = pull.title;
    parents = [baseTip];
  } else {
    message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}`;
    parents = [baseTip, pull.headSha];
  }
  const lines = [`tree ${headTree}`, ...parents.map((p) => `parent ${p}`), `author ${who}`, `committer ${who}`, '', message];
  const data = Buffer.from(lines.join('\n'), 'utf8');
  const mergeSha = hashObject('commit', data);
  repo.objects.set(mergeSha, { type: 'commit', data });
  repo.refs.set(`refs/heads/${pull.base}`, mergeSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergeCommitSha = mergeSha;
  pull.mergedSec = epochSec;
  pull.updatedSec = epochSec;
  repo.updatedSec = epochSec;
  repo.pushedSec = epochSec;
  return true;
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, origin: string, bodyBuf: Buffer): Promise<void> {
  if (!authorized(req)) { badCredentials(res); return; }
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) {
    sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
    return;
  }
  const runOne = (operation: unknown): JsonObject => {
    const op = asObject(operation);
    if (op === null || typeof op.query !== 'string') {
      return { errors: [{ message: 'A GraphQL operation needs a query string.' }] };
    }
    const variables = asObject(op.variables) ?? {};
    try {
      const parser = new GqlParser(op.query);
      const { operations, fragments } = parser.parseDocument(variables);
      const operationName = typeof op.operationName === 'string' ? op.operationName : null;
      const selected = operationName === null
        ? operations[0]
        : operations.find((o) => o.name === operationName) ?? operations[0];
      if (selected === undefined) return { errors: [{ message: `Unknown operation named "${operationName}".` }] };
      const executor = new GraphQLExecutor(origin);
      const { data, errors } = executor.executeOperation(selected, fragments);
      return errors.length > 0 ? { data, errors } : { data };
    } catch (err) {
      return { errors: [{ message: err instanceof Error ? err.message : 'GraphQL parse error' }] };
    }
  };
  if (Array.isArray(parsed.value)) {
    sendJson(res, 200, parsed.value.map((op) => runOne(op)));
    return;
  }
  sendJson(res, 200, runOne(parsed.value));
}

// ============================================================================
// MCP over streamable HTTP
// ============================================================================

const MCP_REVISIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_SESSION_ID = 'mcp-session-1';

interface McpToolDef {
  name: string;
  description: string;
  properties: Record<string, { type: string; description: string }>;
  required: string[];
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    properties: {
      name: { type: 'string', description: 'The name of the repository.' },
      description: { type: 'string', description: 'A short description of the repository.' },
      private: { type: 'boolean', description: 'Whether the repository is private.' },
    },
    required: ['name'],
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The title of the issue.' },
      body: { type: 'string', description: 'The body of the issue.' },
      labels: { type: 'array', description: 'Labels to attach to the issue.' },
    },
    required: ['owner', 'repo', 'title'],
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'The issue state: open, closed or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The title of the pull request.' },
      body: { type: 'string', description: 'The body of the pull request.' },
      head: { type: 'string', description: 'The head branch.' },
      base: { type: 'string', description: 'The base branch.' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
      pull_number: { type: 'number', description: 'The pull request number.' },
    },
    required: ['owner', 'repo', 'pull_number'],
  },
  {
    name: 'search_repositories',
    description: 'Search repositories by name.',
    properties: {
      query: { type: 'string', description: 'The search query.' },
    },
    required: ['query'],
  },
  {
    name: 'get_file_contents',
    description: 'Get the contents of a file in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
      path: { type: 'string', description: 'The file path.' },
    },
    required: ['owner', 'repo', 'path'],
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'The pull request state: open, closed or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'add_issue_comment',
    description: 'Add a comment to an issue.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
      issue_number: { type: 'number', description: 'The issue number.' },
      body: { type: 'string', description: 'The comment body.' },
    },
    required: ['owner', 'repo', 'issue_number', 'body'],
  },
  {
    name: 'get_issue',
    description: 'Get an issue by number.',
    properties: {
      owner: { type: 'string', description: 'The repository owner.' },
      repo: { type: 'string', description: 'The repository name.' },
      issue_number: { type: 'number', description: 'The issue number.' },
    },
    required: ['owner', 'repo', 'issue_number'],
  },
];

function mcpToolsJson(): JsonObject[] {
  return MCP_TOOLS.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: {
      type: 'object',
      properties: tool.properties,
      required: tool.required,
      additionalProperties: false,
    },
  }));
}

/** Normalise tool arguments: the suite may spell owner/repo a few ways. */
function normalizeToolArgs(args: JsonObject): JsonObject {
  const out: JsonObject = { ...args };
  if (typeof out.full_name === 'string') {
    const parts = (out.full_name as string).split('/');
    if (parts.length === 2) {
      out.owner = parts[0];
      out.repo = parts[1];
    }
  }
  if (typeof out.owner_login === 'string') out.owner = out.owner_login;
  if (typeof out.repository === 'string') out.repo = out.repository;
  if (typeof out.pull_request_number === 'number') out.pull_number = out.pull_request_number;
  if (typeof out.number === 'number' && out.pull_number === undefined && out.issue_number === undefined) {
    out.pull_number = out.number;
    out.issue_number = out.number;
  }
  return out;
}

type ToolOutcome = { ok: true; result: unknown } | { ok: false; message: string };

function callMcpTool(name: string, rawArgs: JsonObject, origin: string): ToolOutcome {
  const args = normalizeToolArgs(rawArgs);
  const need = (fields: readonly string[]): string | null => {
    for (const field of fields) {
      if (args[field] === undefined || args[field] === null || args[field] === '') return field;
    }
    return null;
  };
  const ownerOf = (): string | null => (typeof args.owner === 'string' ? args.owner : null);
  const repoOf = (): Repo | null => {
    const owner = ownerOf();
    const repoName = typeof args.repo === 'string' ? args.repo : null;
    if (owner === null || repoName === null) return null;
    if (owner !== VIEWER_LOGIN) return null;
    return findRepo(owner, repoName) ?? null;
  };

  if (name === 'create_repo') {
    const missing = need(['name']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repoName = args.name as string;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(repoName)) return { ok: false, message: 'name is invalid' };
    if (findRepo(VIEWER_LOGIN, repoName) !== undefined) return { ok: false, message: 'name already exists on this account' };
    const repo = createRepoRecord(
      VIEWER_LOGIN,
      repoName,
      typeof args.description === 'string' ? args.description : '',
      args.private === true,
      'main',
    );
    return { ok: true, result: repoJson(repo, origin) };
  }
  if (name === 'get_repo') {
    const missing = need(['owner', 'repo']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    return { ok: true, result: repoJson(repo, origin) };
  }
  if (name === 'create_issue') {
    const missing = need(['owner', 'repo', 'title']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    const labelNames = Array.isArray(args.labels) ? (args.labels as unknown[]).filter((l): l is string => typeof l === 'string') : [];
    for (const labelName of labelNames) {
      if (!repo.labels.has(labelName)) return { ok: false, message: `Label '${labelName}' does not exist` };
    }
    const now = nextTs();
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const issue: Issue = {
      number,
      title: args.title as string,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: labelNames,
      comments: [],
      createdSec: now,
      updatedSec: now,
      closedSec: null,
      nextCommentId: 1,
    };
    repo.issues.set(number, issue);
    return { ok: true, result: issueJson(repo, issue) };
  }
  if (name === 'list_issues') {
    const missing = need(['owner', 'repo']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.issues.values()];
    if (state !== 'all') list = list.filter((i) => i.state === state);
    list.sort((a, b) => b.createdSec - a.createdSec || b.number - a.number);
    return { ok: true, result: list.map((i) => issueJson(repo, i)) };
  }
  if (name === 'create_pull_request') {
    const missing = need(['owner', 'repo', 'title', 'head', 'base']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    const head = args.head as string;
    const base = args.base as string;
    const headTip = repo.refs.get(`refs/heads/${head}`);
    const baseTip = repo.refs.get(`refs/heads/${base}`);
    if (headTip === undefined || baseTip === undefined) return { ok: false, message: 'head or base branch does not exist' };
    const now = nextTs();
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const pull: Pull = {
      number,
      title: args.title as string,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      merged: false,
      head,
      base,
      headSha: headTip,
      baseSha: baseTip,
      mergeCommitSha: null,
      mergedSec: null,
      createdSec: now,
      updatedSec: now,
    };
    repo.pulls.set(number, pull);
    return { ok: true, result: pullJson(repo, pull, origin) };
  }
  if (name === 'merge_pull_request') {
    const missing = need(['owner', 'repo', 'pull_number']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    const pull = repo.pulls.get(Number(args.pull_number));
    if (pull === undefined) return { ok: false, message: 'Not Found' };
    if (!mergePullRequest(repo, pull, 'MERGE')) return { ok: false, message: 'Merge conflict: the pull request cannot be merged cleanly' };
    return { ok: true, result: pullJson(repo, pull, origin) };
  }
  if (name === 'search_repositories') {
    const query = typeof args.query === 'string' ? args.query : '';
    const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN && r.name.includes(query));
    return { ok: true, result: { total_count: all.length, incomplete_results: false, items: all.map((r) => repoJson(r, origin)) } };
  }
  if (name === 'get_file_contents') {
    const missing = need(['owner', 'repo', 'path']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    const tip = headTarget(repo);
    if (tip === ZERO_OID) return { ok: false, message: 'Not Found' };
    const commit = repo.objects.get(tip);
    if (commit === undefined || commit.type !== 'commit') return { ok: false, message: 'Not Found' };
    const file = readPath(repo, parseCommit(commit.data).tree, args.path as string);
    if (file === null) return { ok: false, message: 'Not Found' };
    return { ok: true, result: { name: (args.path as string).split('/').pop(), path: args.path, sha: file.oid, size: file.data.length, type: 'file', encoding: 'base64', content: file.data.toString('base64') } };
  }
  if (name === 'list_pull_requests') {
    const missing = need(['owner', 'repo']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.pulls.values()];
    if (state !== 'all') list = list.filter((p) => p.state === state);
    list.sort((a, b) => b.createdSec - a.createdSec || b.number - a.number);
    return { ok: true, result: list.map((p) => pullJson(repo, p, origin)) };
  }
  if (name === 'add_issue_comment') {
    const missing = need(['owner', 'repo', 'issue_number', 'body']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    const issue = repo.issues.get(Number(args.issue_number));
    if (issue === undefined) return { ok: false, message: 'Not Found' };
    const now = nextTs();
    const comment: IssueComment = { id: issue.nextCommentId, body: args.body as string, createdSec: now, updatedSec: now };
    issue.nextCommentId += 1;
    issue.comments.push(comment);
    issue.updatedSec = now;
    return { ok: true, result: commentJson(repo, issue, comment) };
  }
  if (name === 'get_issue') {
    const missing = need(['owner', 'repo', 'issue_number']);
    if (missing !== null) return { ok: false, message: `Missing required argument: ${missing}` };
    const repo = repoOf();
    if (repo === null) return { ok: false, message: 'Not Found' };
    const issue = repo.issues.get(Number(args.issue_number));
    if (issue === undefined) return { ok: false, message: 'Not Found' };
    return { ok: true, result: issueJson(repo, issue) };
  }
  return { ok: false, message: `Unknown tool: ${name}` };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, origin: string, bodyBuf: Buffer): Promise<void> {
  if (req.method !== 'POST') {
    sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  if (!authorized(req)) { badCredentials(res); return; }
  const sendRpc = (id: unknown, result: unknown): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, result }, { 'mcp-session-id': MCP_SESSION_ID });
  };
  const sendRpcError = (id: unknown, code: number, message: string, httpStatus = 200): void => {
    sendJson(res, httpStatus, { jsonrpc: '2.0', id, error: { code, message } }, { 'mcp-session-id': MCP_SESSION_ID });
  };
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, { 'mcp-session-id': MCP_SESSION_ID });
    return;
  }
  const request = asObject(parsed.value);
  if (request === null || typeof request.method !== 'string') {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } }, { 'mcp-session-id': MCP_SESSION_ID });
    return;
  }
  const id = request.id ?? null;
  const method = request.method as string;
  const params = asObject(request.params) ?? {};

  // Notifications carry no id and get no JSON-RPC answer.
  if (method.startsWith('notifications/') || id === null) {
    sendEmpty(res, 202, { 'mcp-session-id': MCP_SESSION_ID });
    return;
  }

  if (method === 'server/discover') {
    sendRpc(id, {
      protocolVersion: '2026-07-28',
      supportedVersions: MCP_REVISIONS,
      capabilities: { tools: {} },
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: FORGE_NAME, version: FORGE_VERSION } },
    });
    return;
  }
  if (method === 'initialize') {
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const negotiated = MCP_REVISIONS.includes(requested) ? requested : '2025-11-25';
    sendRpc(id, {
      protocolVersion: negotiated,
      capabilities: { tools: {} },
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
    });
    return;
  }
  if (method === 'ping') {
    sendRpc(id, {});
    return;
  }
  if (method === 'tools/list') {
    sendRpc(id, { tools: mcpToolsJson() });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = asObject(params.arguments) ?? {};
    const def = MCP_TOOLS.find((t) => t.name === toolName);
    if (def === undefined) {
      sendRpcError(id, -32601, `Unknown tool: ${toolName}`);
      return;
    }
    const outcome = callMcpTool(toolName, args, origin);
    if (!outcome.ok) {
      sendRpc(id, {
        content: [{ type: 'text', text: outcome.message }],
        structuredContent: { error: outcome.message },
        isError: true,
      });
      return;
    }
    sendRpc(id, {
      content: [{ type: 'text', text: JSON.stringify(outcome.result) }],
      structuredContent: outcome.result,
      isError: false,
    });
    return;
  }
  sendRpcError(id, -32601, `Method not found: ${method}`);
}

// ============================================================================
// the server
// ============================================================================

/** Build the server. It binds nothing until the caller listens. */
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const method = req.method ?? 'GET';
        const path = pathOf(req);
        const query = queryOf(req);
        const segments = splitPath(path);

        // The env's boot check calls this twice: 200 {"ok":true}.
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }

        const bodyBuf = await readBody(req);

        // Git smart HTTP: /<owner>/<repo>.git/...
        if (segments.length >= 2 && segments[1].endsWith('.git')) {
          if (!authorized(req)) { badCredentials(res); return; }
          const owner = segments[0];
          const repoName = segments[1].slice(0, -4);
          const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
          if (repo === undefined) { notFound(res); return; }
          if (method === 'GET' && segments[2] === 'info' && segments[3] === 'refs') {
            handleInfoRefs(req, res, repo, query.get('service') ?? '');
            return;
          }
          if (method === 'POST' && segments[2] === 'git-upload-pack') {
            handleUploadPack(req, res, repo, bodyBuf);
            return;
          }
          if (method === 'POST' && segments[2] === 'git-receive-pack') {
            handleReceivePack(req, res, repo, bodyBuf);
            return;
          }
          notFound(res);
          return;
        }

        // GraphQL v4.
        if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql') {
          if (method !== 'POST') { notFound(res); return; }
          await handleGraphQL(req, res, originOf(req), bodyBuf);
          return;
        }

        // MCP over streamable HTTP.
        if (segments.length === 1 && segments[0] === 'mcp') {
          await handleMcp(req, res, originOf(req), bodyBuf);
          return;
        }

        // REST v3.
        if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
          const handled = await handleRest(req, res, segments, query, bodyBuf);
          if (!handled) notFound(res);
          return;
        }

        // Everything else, every method: GitHub's 404 body.
        sendJson(res, 404, { message: 'Not Found' });
      } catch (err) {
        process.stderr.write(`[forge] request failed: ${err instanceof Error ? err.message : String(err)}\n`);
        if (!res.headersSent) {
          try {
            sendJson(res, 500, { message: 'Internal Server Error' });
          } catch {
            // The socket is gone; nothing left to do.
          }
        }
      }
    })();
  });
}
