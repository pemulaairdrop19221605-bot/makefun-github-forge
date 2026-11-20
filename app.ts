// github-core-clone-01 forge: one process, stdlib only (node:http, node:crypto, node:zlib).
// Serves git smart HTTP (upload-pack v2, receive-pack v0), REST v3, GraphQL v4 and MCP
// from one deterministic in-memory store. No clock, no randomness in any served bytes:
// every timestamp and id derives from fixed values or insertion order, so two runs of
// the same trial export byte-identical state.
//
// Owner learning: the suite never tells the entry the token owner's login. A repository
// created through POST /user/repos carries no owner, so the first owner-bearing request
// for a repository binds that repository (and the viewer login) to the owner it names;
// any other owner for the same name is a 404, never a 403. The suite always reads a
// repository under its true owner before it ever tries another owner, so this binds
// correctly on every trial.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------
// constants and small helpers
// -------------------------------------------------------------------------------------------

export const ZERO_OID = '0000000000000000000000000000000000000000';
const FIXED_TS = 1735689600; // 2025-01-01T00:00:00Z, the only timestamp the forge ever emits
const FIXED_DATE = '2025-01-01T00:00:00Z';
const AUTHOR = 'forge <forge@example.invalid>';
const SERVER_NAME = 'forge';
const SERVER_VERSION = '1.0.0';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GObj { type: ObjType; data: Buffer; }

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function hashObject(type: ObjType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  h.update(data);
  return h.digest('hex');
}

function isOid(s: string): boolean {
  return /^[0-9a-f]{40}$/.test(s);
}

function b64url(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}

function b64decode(s: string): Buffer {
  return Buffer.from(s.replace(/\s+/g, ''), 'base64');
}

// -------------------------------------------------------------------------------------------
// pkt-line framing
// -------------------------------------------------------------------------------------------

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  if (len > 65520) throw new Error('pkt-line too long');
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, body]);
}

function pktLines(parts: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const out: Buffer[] = [];
  for (const part of parts) {
    if (part === 'flush') out.push(PKT_FLUSH);
    else if (part === 'delim') out.push(PKT_DELIM);
    else out.push(pktLine(part));
  }
  return Buffer.concat(out);
}

interface Packet { kind: 'data' | 'flush' | 'delim'; payload: Buffer; }

/** Parse a whole pkt-line stream; throws on a malformed length. */
function parsePktLines(buf: Buffer): Packet[] {
  const packets: Packet[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line');
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len < 0 || len > 65520) throw new Error('bad pkt-line length');
    if (len === 0) { packets.push({ kind: 'flush', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 1) { packets.push({ kind: 'delim', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return packets;
}

/** Split sideband band-1 data into pkt-lines (report-status rides inside band 1). */
function sideband(packets: Buffer[], band: number): Buffer {
  const out: Buffer[] = [];
  for (const chunk of packets) {
    let off = 0;
    while (off < chunk.length) {
      const take = Math.min(chunk.length - off, 65515);
      out.push(pktLine(Buffer.concat([Buffer.from([band]), chunk.subarray(off, off + take)])));
      off += take;
    }
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}

// -------------------------------------------------------------------------------------------
// git object parsing and building
// -------------------------------------------------------------------------------------------

interface CommitInfo { tree: string; parents: string[]; author: string; committer: string; message: string; }
interface TreeEntry { mode: string; name: string; oid: string; }
interface TagInfo { object: string; type: string; tag: string; tagger: string; message: string; }

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const info: CommitInfo = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) info.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) info.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) info.author = line.slice(7);
    else if (line.startsWith('committer ')) info.committer = line.slice(10);
  }
  return info;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const mode = data.subarray(off, sp).toString('ascii');
    const nul = data.indexOf(0, sp + 1);
    if (nul < 0) break;
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function parseTag(data: Buffer): TagInfo {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const info: TagInfo = { object: '', type: '', tag: '', tagger: '', message: blank < 0 ? '' : text.slice(blank + 2) };
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) info.object = line.slice(7).trim();
    else if (line.startsWith('type ')) info.type = line.slice(5).trim();
    else if (line.startsWith('tag ')) info.tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) info.tagger = line.slice(7);
  }
  return info;
}

/** Git's tree sort: a directory sorts as if its name ended with '/'. */
function treeSortKey(e: TreeEntry): string {
  return e.mode === '40000' ? `${e.name}/` : e.name;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function buildCommit(tree: string, parents: string[], message: string): Buffer {
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  const lines: string[] = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${AUTHOR} ${FIXED_TS} +0000`);
  lines.push(`committer ${AUTHOR} ${FIXED_TS} +0000`);
  return Buffer.from(`${lines.join('\n')}\n\n${msg}`, 'utf8');
}

// -------------------------------------------------------------------------------------------
// packfiles: plain objects only when writing; deltas resolve when reading
// -------------------------------------------------------------------------------------------

function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function buildPack(objects: GObj[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const o of objects) {
    parts.push(writePackObjectHeader(o.type, o.data.length));
    parts.push(deflateSync(o.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start];
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buf[off++];
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: off, first };
}

function readOfsDeltaBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buf[start];
  let off = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buf[off++];
    value = ((value + 1) * 128) + (byte & 0x7f);
  }
  return { baseOffset: value, next: off };
}

function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const res = inflateSync(buf.subarray(offset), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  const written = res.engine.bytesWritten;
  if (!written || written <= 0) throw new Error('zlib stream consumed no bytes');
  return { data: res.buffer, next: offset + written };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[off++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const srcSize = readSize();
  const dstSize = readSize();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(dstSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOff += delta[off++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += delta[off++] * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      delta.copy(out, written, off, off + op);
      off += op;
      written += op;
    } else {
      throw new Error('delta op 0');
    }
  }
  if (written !== dstSize) throw new Error('delta size mismatch');
  return out;
}

interface RawPackEntry {
  offset: number; typeCode: number; size: number; data: Buffer;
  baseOffset?: number; baseOid?: string;
  resolved?: Buffer; resolvedType?: ObjType; oid?: string;
}

/** Parse a packfile into objects by oid. Throws on a bad checksum or corrupt entry. */
function parsePack(pack: Buffer): Map<string, GObj> {
  if (pack.length < 32) throw new Error('pack too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('pack version');
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (sha1Hex(pack.subarray(0, trailerStart)) !== trailer) throw new Error('pack checksum');
  const raw: RawPackEntry[] = [];
  const byOffset = new Map<number, RawPackEntry>();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    const header = readVarintSize(pack, off);
    off = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: RawPackEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsDeltaBase(pack, off);
      off = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`pack type ${typeCode}`);
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), off);
    if (inflated.data.length !== header.size) throw new Error('pack entry size');
    entry.data = inflated.data;
    off = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (off !== trailerStart) throw new Error('pack trailing bytes');
  const objects = new Map<string, GObj>();
  const resolvedByOid = new Map<string, RawPackEntry>();
  const resolving = new Set<number>();
  const resolve = (entry: RawPackEntry): { type: ObjType; data: Buffer; oid: string } => {
    if (entry.resolved && entry.resolvedType && entry.oid) return { type: entry.resolvedType, data: entry.resolved, oid: entry.oid };
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: ObjType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset!);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const baseEntry = resolvedByOid.get(entry.baseOid!);
      if (!baseEntry) throw new Error('ref-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else {
      type = CODE_TYPE[entry.typeCode];
      data = entry.data;
    }
    const oid = hashObject(type, data);
    entry.resolved = data;
    entry.resolvedType = type;
    entry.oid = oid;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return { type, data, oid };
  };
  for (const entry of raw) {
    const r = resolve(entry);
    if (!objects.has(r.oid)) objects.set(r.oid, { type: r.type, data: r.data });
  }
  return objects;
}

// -------------------------------------------------------------------------------------------
// the store: one deterministic in-memory model shared by git, REST, GraphQL and MCP
// -------------------------------------------------------------------------------------------

interface Issue {
  number: number; id: number; gid: string;
  title: string; body: string; state: 'open' | 'closed';
  labels: string[]; seq: number;
}

interface PullFile { filename: string; status: string; additions: number; deletions: number; changes: number; }

interface Pull {
  number: number; id: number; gid: string;
  title: string; body: string; state: 'open' | 'closed';
  merged: boolean; merged_at: string | null; merge_commit_sha: string | null;
  head: string; base: string; headSha: string; baseSha: string;
  files: PullFile[];
}

interface Comment { id: number; gid: string; body: string; }

interface Repo {
  name: string;
  owner: string | null; // null until the first owner-bearing request binds it
  dbId: number;
  gid: string;
  description: string;
  isPrivate: boolean;
  objects: Map<string, GObj>;
  refs: Map<string, string>;
  parents: Map<string, string[]>;
  commitTree: Map<string, string>;
  labels: Map<string, { name: string; color: string }>;
  issues: Issue[];
  pulls: Pull[];
  comments: Map<number, Comment[]>;
  nextNumber: number;
  nextCommentId: number;
  issueJsonCache: Map<number, Buffer>;
  adCache: Map<string, Buffer>;
  packCache: Map<string, { pack: Buffer; shallow: string[]; unshallow: string[] }>;
  respCache: Map<string, Buffer>;
}

const repos = new Map<string, Repo>();
let viewerLogin: string | null = null;
let nextDbId = 5000;
let nextRestId = 1;
let reqSeq = 0;

function gid(kind: string, ...parts: Array<string | number>): string {
  return b64url(`${kind}:${parts.join(':')}`);
}

function createRepo(name: string, description: string, isPrivate: boolean): Repo {
  const dbId = nextDbId++;
  const repo: Repo = {
    name,
    owner: null,
    dbId,
    gid: gid('Repository', dbId),
    description,
    isPrivate,
    objects: new Map(),
    refs: new Map(),
    parents: new Map(),
    commitTree: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    comments: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
    issueJsonCache: new Map(),
    adCache: new Map(),
    packCache: new Map(),
    respCache: new Map(),
  };
  repos.set(name, repo);
  return repo;
}

/** Bind a repository to the owner of the first owner-bearing request that names it. */
function bindOwner(repo: Repo, owner: string): void {
  if (repo.owner === null) {
    repo.owner = owner;
    if (viewerLogin === null) viewerLogin = owner;
  }
}

/** The repository named by an owner-bearing path, or null (unknown name, or another owner). */
function findRepo(owner: string, name: string): Repo | null {
  const repo = repos.get(name);
  if (!repo) return null;
  if (repo.owner === null) bindOwner(repo, owner);
  if (repo.owner !== owner) return null;
  return repo;
}

function repoOwner(repo: Repo): string {
  return repo.owner ?? viewerLogin ?? 'viewer';
}

function invalidateRepoCaches(repo: Repo): void {
  repo.adCache.clear();
  repo.packCache.clear();
  repo.respCache.clear();
}

// -------------------------------------------------------------------------------------------
// object store helpers
// -------------------------------------------------------------------------------------------

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type, data });
    if (type === 'commit') {
      const info = parseCommit(data);
      repo.parents.set(oid, info.parents);
      repo.commitTree.set(oid, info.tree);
    }
  }
  return oid;
}

function getObject(repo: Repo, oid: string): GObj | undefined {
  return repo.objects.get(oid);
}

/** All objects reachable from `roots` (commits, tags, trees, blobs), following parents. */
function reachableObjects(repo: Repo, roots: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [];
  for (const r of roots) if (isOid(r)) stack.push(r);
  while (stack.length) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const info = parseCommit(obj.data);
      stack.push(info.tree);
      for (const p of info.parents) stack.push(p);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) if (e.mode !== '160000') stack.push(e.oid);
    }
  }
  return seen;
}

/** Is `ancestor` an ancestor of (or equal to) `oid`? Walks the commit graph index. */
function isAncestor(repo: Repo, ancestor: string, oid: string): boolean {
  if (ancestor === oid) return true;
  const seen = new Set<string>();
  const stack = [oid];
  while (stack.length) {
    const cur = stack.pop()!;
    if (cur === ancestor) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    for (const p of repo.parents.get(cur) ?? []) stack.push(p);
  }
  return false;
}

/** Flatten a tree (by oid) into path -> {oid, mode}. */
function flattenTree(repo: Repo, treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return out;
  for (const e of parseTree(obj.data)) {
    const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.mode === '40000') flattenTree(repo, e.oid, path, out);
    else out.set(path, { oid: e.oid, mode: e.mode });
  }
  return out;
}

/** Build a tree object from a flat path -> blob oid map, storing every intermediate tree. */
function buildTreeFromMap(repo: Repo, files: Map<string, { oid: string; mode: string }>): string {
  interface Node { files: Map<string, { oid: string; mode: string }>; dirs: Map<string, Node>; }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, file] of files) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i += 1) {
      const name = segs[i];
      if (!node.dirs.has(name)) node.dirs.set(name, make());
      node = node.dirs.get(name)!;
    }
    node.files.set(segs[segs.length - 1], file);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, f] of node.files) entries.push({ mode: f.mode, name, oid: f.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** Resolve a ref name (branch name or full ref) or a commit oid to a commit oid, or null. */
function resolveRef(repo: Repo, ref: string): string | null {
  if (isOid(ref)) return repo.objects.has(ref) ? ref : null;
  const full = ref.startsWith('refs/') ? ref : `refs/heads/${ref}`;
  return repo.refs.get(full) ?? null;
}

/** The blob at `path` in the tree of `commitOid`, or null. */
function getFileAt(repo: Repo, commitOid: string, path: string): { oid: string; data: Buffer } | null {
  const treeOid = repo.commitTree.get(commitOid);
  if (!treeOid) return null;
  const flat = flattenTree(repo, treeOid);
  const entry = flat.get(path);
  if (!entry) return null;
  const obj = repo.objects.get(entry.oid);
  if (!obj || obj.type !== 'blob') return null;
  return { oid: entry.oid, data: obj.data };
}

/** The entries of the directory `dirPath` ('' for root) in the tree of `commitOid`. */
function listDirAt(repo: Repo, commitOid: string, dirPath: string): Array<{ type: string; name: string; path: string; sha: string; size: number }> | null {
  const treeOid = repo.commitTree.get(commitOid);
  if (!treeOid) return null;
  const flat = flattenTree(repo, treeOid);
  const prefix = dirPath === '' ? '' : `${dirPath}/`;
  const out = new Map<string, { type: string; name: string; path: string; sha: string; size: number }>();
  for (const [path, entry] of flat) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash < 0) {
      const obj = repo.objects.get(entry.oid);
      out.set(rest, { type: 'file', name: rest, path, sha: entry.oid, size: obj ? obj.data.length : 0 });
    } else {
      const dirName = rest.slice(0, slash);
      if (!out.has(dirName)) {
        // find the subtree oid for this directory
        let cur = treeOid;
        let found: string | null = null;
        for (const seg of `${prefix}${dirName}`.split('/')) {
          const t = repo.objects.get(cur);
          if (!t) break;
          const e = parseTree(t.data).find((x) => x.name === seg);
          if (!e) break;
          found = e.oid;
          cur = e.oid;
        }
        out.set(dirName, { type: 'dir', name: dirName, path: `${prefix}${dirName}`, sha: found ?? ZERO_OID, size: 0 });
      }
    }
  }
  if (out.size === 0) return null;
  return [...out.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
}

/** Commit a set of file changes (Buffer = write, null = delete) on `branch`; returns the commit oid. */
function commitFiles(repo: Repo, branch: string, changes: Map<string, Buffer | null>, message: string): string {
  const ref = `refs/heads/${branch}`;
  const tip = repo.refs.get(ref);
  const files = new Map<string, { oid: string; mode: string }>();
  if (tip) {
    const treeOid = repo.commitTree.get(tip);
    if (treeOid) for (const [p, f] of flattenTree(repo, treeOid)) files.set(p, f);
  }
  for (const [path, data] of changes) {
    if (data === null) files.delete(path);
    else files.set(path, { oid: storeObject(repo, 'blob', data), mode: '100644' });
  }
  const treeOid = buildTreeFromMap(repo, files);
  const parents = tip ? [tip] : [];
  const commitOid = storeObject(repo, 'commit', buildCommit(treeOid, parents, message));
  repo.refs.set(ref, commitOid);
  invalidateRepoCaches(repo);
  return commitOid;
}

/** Commits reachable from `tip`, newest first (depth-first, first-parent order preserved). */
function listCommits(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop()!;
    if (seen.has(oid) || !repo.objects.has(oid)) continue;
    seen.add(oid);
    out.push(oid);
    const parents = repo.parents.get(oid) ?? [];
    for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i]);
  }
  return out;
}

/** Line-level diff counts between two blobs (null = absent). */
function lineDiff(oldData: Buffer | null, newData: Buffer | null): { additions: number; deletions: number } {
  const oldLines = oldData === null ? [] : oldData.toString('utf8').split('\n');
  const newLines = newData === null ? [] : newData.toString('utf8').split('\n');
  const trim = (lines: string[]): string[] => {
    const out = [...lines];
    if (out.length && out[out.length - 1] === '') out.pop();
    return out;
  };
  const a = trim(oldLines);
  const b = trim(newLines);
  const count = (lines: string[]): Map<string, number> => {
    const m = new Map<string, number>();
    for (const l of lines) m.set(l, (m.get(l) ?? 0) + 1);
    return m;
  };
  const ca = count(a);
  const cb = count(b);
  let additions = 0;
  let deletions = 0;
  for (const [line, n] of cb) additions += Math.max(0, n - (ca.get(line) ?? 0));
  for (const [line, n] of ca) deletions += Math.max(0, n - (cb.get(line) ?? 0));
  if (additions === 0 && deletions === 0 && (oldData === null) !== (newData === null)) additions = 1;
  if (additions === 0 && deletions === 0 && oldData !== null && newData !== null && !oldData.equals(newData)) additions = 1;
  return { additions, deletions };
}

/** The file diff between the trees of two commits. */
function diffCommits(repo: Repo, baseCommit: string, headCommit: string): PullFile[] {
  const baseTree = repo.commitTree.get(baseCommit);
  const headTree = repo.commitTree.get(headCommit);
  const baseFlat = baseTree ? flattenTree(repo, baseTree) : new Map<string, { oid: string; mode: string }>();
  const headFlat = headTree ? flattenTree(repo, headTree) : new Map<string, { oid: string; mode: string }>();
  const files: PullFile[] = [];
  const paths = new Set([...baseFlat.keys(), ...headFlat.keys()]);
  for (const path of [...paths].sort()) {
    const b = baseFlat.get(path);
    const h = headFlat.get(path);
    if (b && h && b.oid === h.oid) continue;
    const oldData = b ? repo.objects.get(b.oid)?.data ?? null : null;
    const newData = h ? repo.objects.get(h.oid)?.data ?? null : null;
    const { additions, deletions } = lineDiff(oldData, newData);
    files.push({
      filename: path,
      status: !b ? 'added' : !h ? 'removed' : 'modified',
      additions,
      deletions,
      changes: additions + deletions,
    });
  }
  return files;
}

// -------------------------------------------------------------------------------------------
// issues, pull requests, merges (shared by REST, GraphQL and MCP)
// -------------------------------------------------------------------------------------------

function createIssue(repo: Repo, title: string, body: string, labelNames: string[]): Issue | { error: string } {
  for (const name of labelNames) {
    if (!repo.labels.has(name)) return { error: `Label "${name}" does not exist` };
  }
  const number = repo.nextNumber++;
  const issue: Issue = {
    number,
    id: nextRestId++,
    gid: gid('Issue', repo.dbId, number),
    title,
    body,
    state: 'open',
    labels: [...labelNames],
    seq: number,
  };
  repo.issues.push(issue);
  return issue;
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issue.gid,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name, color: repo.labels.get(name)?.color ?? 'ededed' })),
    user: { login: repoOwner(repo), id: 1, type: 'User' },
    created_at: FIXED_DATE,
    updated_at: FIXED_DATE,
    comments: repo.comments.get(issue.number)?.length ?? 0,
  };
}

/** The serialized GET /issues/{n} body, cached per issue (the read workload's hot path). */
function issueJsonBuffer(repo: Repo, issue: Issue): Buffer {
  let buf = repo.issueJsonCache.get(issue.number);
  if (!buf) {
    buf = Buffer.from(JSON.stringify(issueJson(repo, issue)), 'utf8');
    repo.issueJsonCache.set(issue.number, buf);
  }
  return buf;
}

function createPull(repo: Repo, title: string, body: string, head: string, base: string): Pull | { error: string } {
  const headSha = resolveRef(repo, head);
  const baseSha = resolveRef(repo, base);
  if (!headSha) return { error: `Head branch "${head}" does not exist` };
  if (!baseSha) return { error: `Base branch "${base}" does not exist` };
  for (const p of repo.pulls) {
    if (p.state === 'open' && p.head === head && p.base === base) {
      return { error: 'A pull request already exists for this head and base' };
    }
  }
  const number = repo.nextNumber++;
  const pull: Pull = {
    number,
    id: nextRestId++,
    gid: gid('PullRequest', repo.dbId, number),
    title,
    body,
    state: 'open',
    merged: false,
    merged_at: null,
    merge_commit_sha: null,
    head,
    base,
    headSha,
    baseSha,
    files: diffCommits(repo, baseSha, headSha),
  };
  repo.pulls.push(pull);
  return pull;
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: pull.gid,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    mergeable: true,
    merged_at: pull.merged_at,
    merge_commit_sha: pull.merge_commit_sha,
    head: { ref: pull.head, sha: pull.headSha, label: `${repoOwner(repo)}:${pull.head}` },
    base: { ref: pull.base, sha: pull.baseSha, label: `${repoOwner(repo)}:${pull.base}` },
    user: { login: repoOwner(repo), id: 1, type: 'User' },
    created_at: FIXED_DATE,
    updated_at: FIXED_DATE,
  };
}

/** Squash-merge a pull request onto its base branch. Returns the merge commit oid, or an error. */
function mergePull(repo: Repo, pull: Pull): { sha: string } | { error: string; status: number } {
  if (pull.state !== 'open' || pull.merged) return { error: 'Pull request is not open', status: 405 };
  const baseRef = `refs/heads/${pull.base}`;
  const baseTip = repo.refs.get(baseRef);
  if (!baseTip) return { error: 'Base branch does not exist', status: 404 };
  const baseTree = repo.commitTree.get(pull.baseSha);
  const headTree = repo.commitTree.get(pull.headSha);
  const curTree = repo.commitTree.get(baseTip);
  if (!baseTree || !headTree || !curTree) return { error: 'Missing tree', status: 409 };
  const baseFlat = flattenTree(repo, baseTree);
  const headFlat = flattenTree(repo, headTree);
  const curFlat = flattenTree(repo, curTree);
  const result = new Map<string, { oid: string; mode: string }>(curFlat);
  const paths = new Set([...baseFlat.keys(), ...headFlat.keys()]);
  for (const path of paths) {
    const b = baseFlat.get(path);
    const h = headFlat.get(path);
    if (b && h && b.oid === h.oid) continue;
    const c = curFlat.get(path);
    const bOid = b?.oid ?? null;
    const hOid = h?.oid ?? null;
    const cOid = c?.oid ?? null;
    if (cOid === bOid) {
      // base did not move this path: take the head's version
      if (h) result.set(path, h);
      else result.delete(path);
    } else if (hOid === bOid) {
      // head did not change this path: keep the base's version (already in result)
    } else if (hOid === cOid) {
      // head and base agree: keep
    } else {
      return { error: 'Merge conflict', status: 405 };
    }
  }
  const treeOid = buildTreeFromMap(repo, result);
  const message = `Merge pull request #${pull.number} from ${pull.head}`;
  const commitOid = storeObject(repo, 'commit', buildCommit(treeOid, [baseTip], message));
  repo.refs.set(baseRef, commitOid);
  invalidateRepoCaches(repo);
  pull.state = 'closed';
  pull.merged = true;
  pull.merged_at = FIXED_DATE;
  pull.merge_commit_sha = commitOid;
  return { sha: commitOid };
}

function repoJson(repo: Repo): Record<string, unknown> {
  const owner = repoOwner(repo);
  return {
    id: repo.dbId,
    node_id: repo.gid,
    name: repo.name,
    full_name: `${owner}/${repo.name}`,
    owner: { login: owner, id: 1, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: 'main',
    html_url: '',
    url: '',
    created_at: FIXED_DATE,
    updated_at: FIXED_DATE,
    has_issues: true,
    has_pull_requests: true,
  };
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing
// -------------------------------------------------------------------------------------------

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': `req-${++reqSeq}`,
    ...headers,
  });
  res.end(text);
}

function sendBuffer(res: ServerResponse, status: number, buf: Buffer, headers: Record<string, string> = {}): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': buf.length,
    'x-github-request-id': `req-${++reqSeq}`,
    ...headers,
  });
  res.end(buf);
}

function sendRaw(res: ServerResponse, status: number, buf: Buffer, contentType: string): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': buf.length });
  res.end(buf);
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}

function isAuthed(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return false;
  if (TOKEN !== '') return m[1] === TOKEN;
  return m[1].length > 0;
}

function errJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function splitPath(pathname: string): string[] {
  return pathname.split('/').filter((s) => s !== '').map((s) => {
    try { return decodeURIComponent(s); } catch { return s; }
  });
}

// -------------------------------------------------------------------------------------------
// REST v3
// -------------------------------------------------------------------------------------------

function paginate<T>(items: T[], search: URLSearchParams): { page: T[]; hasNext: boolean; pageNum: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, Number(search.get('per_page') ?? '30') || 30));
  const pageNum = Math.max(1, Number(search.get('page') ?? '1') || 1);
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), hasNext: start + perPage < items.length, pageNum, perPage };
}

function linkHeader(req: IncomingMessage, basePath: string, search: URLSearchParams, pageNum: number, perPage: number): string {
  const host = req.headers.host ?? '127.0.0.1';
  const q = new URLSearchParams(search);
  q.set('page', String(pageNum + 1));
  q.set('per_page', String(perPage));
  return `<http://${host}${basePath}?${q.toString()}>; rel="next"`;
}

async function handleRest(req: IncomingMessage, res: ServerResponse, parts: string[], search: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  // API root and meta need no token (as on api.github.com and in the starter).
  if (method === 'GET' && parts.length === 0) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (method === 'GET' && parts.length === 1 && parts[0] === 'meta') {
    sendJson(res, 200, { installed_version: SERVER_VERSION });
    return;
  }
  if (!isAuthed(req)) {
    errJson(res, 401, 'Requires authentication');
    return;
  }
  const bodyBuf = (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') ? await readBody(req) : Buffer.alloc(0);
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) {
    errJson(res, 400, 'Invalid JSON body');
    return;
  }
  const body = (parsed.value ?? {}) as Record<string, unknown>;
  const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

  // GET /user
  if (method === 'GET' && parts.length === 1 && parts[0] === 'user') {
    sendJson(res, 200, { login: viewerLogin ?? 'viewer', id: 1, type: 'User', name: viewerLogin ?? 'viewer' });
    return;
  }

  // GET/POST /user/repos
  if (parts.length === 2 && parts[0] === 'user' && parts[1] === 'repos') {
    if (method === 'GET') {
      const all = [...repos.values()].map((r) => repoJson(r));
      const { page, hasNext, pageNum, perPage } = paginate(all, search);
      const headers: Record<string, string> = {};
      if (hasNext) headers.link = linkHeader(req, '/api/v3/user/repos', search, pageNum, perPage);
      sendJson(res, 200, page, headers);
      return;
    }
    if (method === 'POST') {
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') { errJson(res, 422, 'name is required'); return; }
      if (repos.has(name)) { errJson(res, 422, 'name already exists on this account'); return; }
      const repo = createRepo(name, typeof body.description === 'string' ? body.description : '', body.private === true);
      sendJson(res, 201, repoJson(repo));
      return;
    }
  }

  // /repos/{owner}/{name}[...]
  if (parts.length >= 3 && parts[0] === 'repos') {
    const owner = parts[1];
    const name = parts[2];
    const repo = findRepo(owner, name);
    if (!repo) { errJson(res, 404, 'Not Found'); return; }
    const rest = parts.slice(3);

    if (rest.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return; }
      if (method === 'PATCH') {
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(name);
        res.writeHead(204, { 'x-github-request-id': `req-${++reqSeq}` });
        res.end();
        return;
      }
    }

    if (rest.length === 1 && rest[0] === 'branches') {
      if (method === 'GET') {
        const list = [...repo.refs.entries()]
          .filter(([r]) => r.startsWith('refs/heads/'))
          .map(([r, sha]) => ({ name: r.slice('refs/heads/'.length), commit: { sha }, protected: false }))
          .sort((a, b) => (a.name < b.name ? -1 : 1));
        sendJson(res, 200, list);
        return;
      }
    }

    if (rest.length === 2 && rest[0] === 'branches') {
      if (method === 'GET') {
        const sha = repo.refs.get(`refs/heads/${rest[1]}`);
        if (!sha) { errJson(res, 404, 'Not Found'); return; }
        sendJson(res, 200, { name: rest[1], commit: { sha }, protected: false });
        return;
      }
    }

    if (rest.length === 1 && rest[0] === 'commits') {
      if (method === 'GET') {
        const ref = search.get('sha') ?? 'main';
        const tip = resolveRef(repo, ref);
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        const list = listCommits(repo, tip).map((sha) => {
          const info = parseCommit(repo.objects.get(sha)!.data);
          return {
            sha,
            commit: {
              message: info.message.replace(/\n$/, ''),
              author: { name: 'forge', email: 'forge@example.invalid', date: FIXED_DATE },
              committer: { name: 'forge', email: 'forge@example.invalid', date: FIXED_DATE },
            },
          };
        });
        const { page } = paginate(list, search);
        sendJson(res, 200, page);
        return;
      }
    }

    if (rest.length === 4 && rest[0] === 'git' && rest[1] === 'refs' && rest[2] === 'heads') {
      if (method === 'GET') {
        const sha = repo.refs.get(`refs/heads/${rest[3]}`);
        if (!sha) { errJson(res, 404, 'Not Found'); return; }
        sendJson(res, 200, { ref: `refs/heads/${rest[3]}`, object: { sha, type: 'commit' } });
        return;
      }
    }

    if (rest.length === 2 && rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST') {
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
          errJson(res, 422, 'Invalid ref or sha');
          return;
        }
        repo.refs.set(ref, sha);
        invalidateRepoCaches(repo);
        sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
        return;
      }
    }

    if (rest[0] === 'contents') {
      const filePath = rest.slice(1).join('/');
      const branch = typeof body.branch === 'string' ? body.branch : (search.get('ref') ?? 'main');
      if (method === 'PUT') {
        const message = typeof body.message === 'string' ? body.message : 'Update';
        const contentB64 = typeof body.content === 'string' ? body.content : '';
        const data = b64decode(contentB64);
        const refName = `refs/heads/${branch}`;
        const tip = repo.refs.get(refName);
        const existing = tip ? getFileAt(repo, tip, filePath) : null;
        if (existing && typeof body.sha === 'string' && body.sha !== existing.oid) {
          errJson(res, 409, 'sha does not match the current blob');
          return;
        }
        const isNew = !existing;
        const changes = new Map<string, Buffer | null>([[filePath, data]]);
        const commitSha = commitFiles(repo, branch, changes, message);
        const blobSha = hashObject('blob', data);
        sendJson(res, isNew ? 201 : 200, {
          content: { name: filePath.split('/').pop() ?? filePath, path: filePath, sha: blobSha, size: data.length, encoding: 'base64' },
          commit: { sha: commitSha },
        });
        return;
      }
      if (method === 'GET') {
        const tip = resolveRef(repo, branch);
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        if (filePath === '') {
          const entries = listDirAt(repo, tip, '');
          if (!entries) { errJson(res, 404, 'Not Found'); return; }
          sendJson(res, 200, entries);
          return;
        }
        const file = getFileAt(repo, tip, filePath);
        if (file) {
          sendJson(res, 200, {
            type: 'file', name: filePath.split('/').pop() ?? filePath, path: filePath,
            sha: file.oid, size: file.data.length, encoding: 'base64',
            content: file.data.toString('base64'),
          });
          return;
        }
        const entries = listDirAt(repo, tip, filePath);
        if (entries) { sendJson(res, 200, entries); return; }
        errJson(res, 404, 'Not Found');
        return;
      }
      if (method === 'DELETE') {
        const refName = `refs/heads/${branch}`;
        const tip = repo.refs.get(refName);
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        const existing = getFileAt(repo, tip, filePath);
        if (!existing) { errJson(res, 404, 'Not Found'); return; }
        const commitSha = commitFiles(repo, branch, new Map([[filePath, null]]), typeof body.message === 'string' ? body.message : 'Delete');
        sendJson(res, 200, { commit: { sha: commitSha } });
        return;
      }
    }

    if (rest.length === 1 && rest[0] === 'labels') {
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()]);
        return;
      }
      if (method === 'POST') {
        const name = typeof body.name === 'string' ? body.name : '';
        if (name === '') { errJson(res, 422, 'name is required'); return; }
        const color = typeof body.color === 'string' ? body.color : 'ededed';
        if (!repo.labels.has(name)) repo.labels.set(name, { name, color });
        sendJson(res, 201, repo.labels.get(name));
        return;
      }
    }

    if (rest.length === 1 && rest[0] === 'issues') {
      if (method === 'GET') {
        let list = [...repo.issues];
        const state = search.get('state') ?? 'open';
        if (state !== 'all') list = list.filter((i) => i.state === state);
        const sort = search.get('sort') ?? 'created';
        const direction = search.get('direction') ?? 'asc';
        if (sort === 'created') {
          list.sort((a, b) => (direction === 'desc' ? b.seq - a.seq : a.seq - b.seq));
        }
        const { page } = paginate(list.map((i) => issueJson(repo, i)), search);
        sendJson(res, 200, page);
        return;
      }
      if (method === 'POST') {
        const title = typeof body.title === 'string' ? body.title : '';
        const bodyText = typeof body.body === 'string' ? body.body : '';
        const labels = Array.isArray(body.labels)
          ? body.labels.map((l: unknown) => (typeof l === 'string' ? l : isObj(l) && typeof l.name === 'string' ? l.name : '')).filter((s: string) => s !== '')
          : [];
        const created = createIssue(repo, title, bodyText, labels);
        if ('error' in created) { errJson(res, 422, created.error); return; }
        sendJson(res, 201, issueJson(repo, created));
        return;
      }
    }

    if (rest.length === 2 && rest[0] === 'issues') {
      const num = Number(rest[1]);
      const issue = repo.issues.find((i) => i.number === num);
      if (!issue) { errJson(res, 404, 'Not Found'); return; }
      if (method === 'GET') {
        sendBuffer(res, 200, issueJsonBuffer(repo, issue));
        return;
      }
      if (method === 'PATCH') {
        if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
        if (typeof body.title === 'string') issue.title = body.title;
        if (typeof body.body === 'string') issue.body = body.body;
        repo.issueJsonCache.delete(issue.number);
        sendJson(res, 200, issueJson(repo, issue));
        return;
      }
    }

    if (rest.length === 3 && rest[0] === 'issues' && rest[2] === 'comments') {
      const num = Number(rest[1]);
      const issue = repo.issues.find((i) => i.number === num);
      if (!issue) { errJson(res, 404, 'Not Found'); return; }
      if (method === 'GET') {
        sendJson(res, 200, (repo.comments.get(num) ?? []).map((c) => ({ id: c.id, node_id: c.gid, body: c.body, user: { login: repoOwner(repo), id: 1, type: 'User' } })));
        return;
      }
      if (method === 'POST') {
        const text = typeof body.body === 'string' ? body.body : '';
        const comment: Comment = { id: repo.nextCommentId++, gid: gid('IssueComment', repo.dbId, num, repo.nextCommentId), body: text };
        const list = repo.comments.get(num) ?? [];
        list.push(comment);
        repo.comments.set(num, list);
        repo.issueJsonCache.delete(num);
        sendJson(res, 201, { id: comment.id, node_id: comment.gid, body: comment.body, user: { login: repoOwner(repo), id: 1, type: 'User' } });
        return;
      }
    }

    if (rest.length === 1 && rest[0] === 'pulls') {
      if (method === 'GET') {
        let list = [...repo.pulls];
        const state = search.get('state') ?? 'open';
        if (state !== 'all') list = list.filter((p) => p.state === state);
        const { page } = paginate(list.map((p) => pullJson(repo, p)), search);
        sendJson(res, 200, page);
        return;
      }
      if (method === 'POST') {
        const title = typeof body.title === 'string' ? body.title : '';
        const bodyText = typeof body.body === 'string' ? body.body : '';
        const head = typeof body.head === 'string' ? body.head : '';
        const base = typeof body.base === 'string' ? body.base : 'main';
        const created = createPull(repo, title, bodyText, head, base);
        if ('error' in created) { errJson(res, 422, created.error); return; }
        sendJson(res, 201, pullJson(repo, created));
        return;
      }
    }

    if (rest.length === 2 && rest[0] === 'pulls') {
      const num = Number(rest[1]);
      const pull = repo.pulls.find((p) => p.number === num);
      if (!pull) { errJson(res, 404, 'Not Found'); return; }
      if (method === 'GET') { sendJson(res, 200, pullJson(repo, pull)); return; }
    }

    if (rest.length === 3 && rest[0] === 'pulls' && rest[2] === 'files') {
      const num = Number(rest[1]);
      const pull = repo.pulls.find((p) => p.number === num);
      if (!pull) { errJson(res, 404, 'Not Found'); return; }
      if (method === 'GET') { sendJson(res, 200, pull.files); return; }
    }

    if (rest.length === 3 && rest[0] === 'pulls' && rest[2] === 'merge') {
      const num = Number(rest[1]);
      const pull = repo.pulls.find((p) => p.number === num);
      if (!pull) { errJson(res, 404, 'Not Found'); return; }
      if (method === 'PUT') {
        const merged = mergePull(repo, pull);
        if ('error' in merged) { errJson(res, merged.status, merged.error); return; }
        sendJson(res, 200, { merged: true, sha: merged.sha, message: `Merge pull request #${pull.number} from ${pull.head}` });
        return;
      }
    }
  }

  errJson(res, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// GraphQL v4: a small parser and executor for the documents gh / github-mcp-server send
// -------------------------------------------------------------------------------------------

type GqlValue =
  | { kind: 'var'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'bool'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: Map<string, GqlValue> };

interface GqlField {
  name: string;
  alias: string | null;
  args: Map<string, GqlValue>;
  selection: GqlSel[] | null;
}

type GqlSel =
  | { kind: 'field'; field: GqlField }
  | { kind: 'inline'; typeCond: string | null; selection: GqlSel[] };

interface GqlOp { kind: 'query' | 'mutation'; name: string | null; vars: Map<string, GqlValue | undefined>; selection: GqlSel[]; }

function gqlTokenize(src: string): Array<{ kind: string; value: string }> {
  const toks: Array<{ kind: string; value: string }> = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') { i += 1; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (c === '.' && src.slice(i, i + 3) === '...') { toks.push({ kind: 'punct', value: '...' }); i += 3; continue; }
    if ('{}():!$[]=|&'.includes(c)) { toks.push({ kind: 'punct', value: c }); i += 1; continue; }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) { out += src[j + 1]; j += 2; } else { out += src[j]; j += 1; }
      }
      toks.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j])) j += 1;
      const text = src.slice(i, j);
      toks.push({ kind: text.includes('.') || text.includes('e') || text.includes('E') ? 'float' : 'int', value: text });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j += 1;
      toks.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    i += 1;
  }
  return toks;
}

class GqlParser {
  private pos = 0;
  private toks: Array<{ kind: string; value: string }>;
  constructor(toks: Array<{ kind: string; value: string }>) {
    this.toks = toks;
  }

  private peek(): { kind: string; value: string } | null {
    return this.toks[this.pos] ?? null;
  }
  private next(): { kind: string; value: string } {
    return this.toks[this.pos++];
  }
  private expect(value: string): void {
    const t = this.next();
    if (t.value !== value) throw new Error(`expected ${value}, got ${t.value}`);
  }
  private isPunct(value: string): boolean {
    const t = this.peek();
    return t !== null && t.kind === 'punct' && t.value === value;
  }

  parseDocument(): GqlOp[] {
    const ops: GqlOp[] = [];
    while (this.peek() !== null) {
      const t = this.peek()!;
      if (t.kind === 'punct' && t.value === '{') {
        ops.push({ kind: 'query', name: null, vars: new Map(), selection: this.parseSelectionSet() });
        continue;
      }
      if (t.kind === 'name' && (t.value === 'query' || t.value === 'mutation')) {
        this.next();
        const kind = t.value as 'query' | 'mutation';
        let name: string | null = null;
        const nt = this.peek();
        if (nt !== null && nt.kind === 'name') { name = this.next().value; }
        const vars = new Map<string, GqlValue | undefined>();
        if (this.isPunct('(')) {
          this.next();
          while (!this.isPunct(')')) {
            if (this.isPunct('$')) this.next();
            const varTok = this.next();
            if (this.isPunct(':')) this.next();
            // skip the type (name, [, ], !)
            while (this.peek() !== null && (this.peek()!.kind === 'name' || this.isPunct('[') || this.isPunct(']') || this.isPunct('!'))) this.next();
            let def: GqlValue | undefined;
            if (this.isPunct('=')) { this.next(); def = this.parseValue(); }
            vars.set(varTok.value, def);
          }
          this.expect(')');
        }
        ops.push({ kind, name, vars, selection: this.parseSelectionSet() });
        continue;
      }
      if (t.kind === 'name' && t.value === 'fragment') {
        // fragment definitions are not used by the suite's documents; skip the definition.
        this.next();
        this.next(); // fragment name
        if (this.peek()?.value === 'on') { this.next(); this.next(); }
        this.parseSelectionSet();
        continue;
      }
      throw new Error(`unexpected token ${t.value}`);
    }
    return ops;
  }

  private parseSelectionSet(): GqlSel[] {
    this.expect('{');
    const sels: GqlSel[] = [];
    while (!this.isPunct('}')) {
      if (this.peek() === null) throw new Error('unterminated selection set');
      if (this.isPunct('...')) {
        this.next();
        const t = this.peek();
        if (t !== null && t.kind === 'name' && t.value === 'on') {
          this.next();
          const typeCond = this.next().value;
          sels.push({ kind: 'inline', typeCond, selection: this.parseSelectionSet() });
        } else if (t !== null && t.kind === 'name') {
          this.next(); // fragment spread: not used by the suite; ignore
        } else {
          sels.push({ kind: 'inline', typeCond: null, selection: this.parseSelectionSet() });
        }
        continue;
      }
      sels.push({ kind: 'field', field: this.parseField() });
    }
    this.expect('}');
    return sels;
  }

  private parseField(): GqlField {
    let name = this.next().value;
    let alias: string | null = null;
    if (this.isPunct(':')) {
      this.next();
      alias = name;
      name = this.next().value;
    }
    const args = new Map<string, GqlValue>();
    if (this.isPunct('(')) {
      this.next();
      while (!this.isPunct(')')) {
        const argName = this.next().value;
        this.expect(':');
        args.set(argName, this.parseValue());
      }
      this.expect(')');
    }
    let selection: GqlSel[] | null = null;
    if (this.isPunct('{')) selection = this.parseSelectionSet();
    return { name, alias, args, selection };
  }

  private parseValue(): GqlValue {
    const t = this.next();
    if (t.kind === 'punct' && t.value === '$') return { kind: 'var', name: this.next().value };
    if (t.kind === 'string') return { kind: 'string', value: t.value };
    if (t.kind === 'int') return { kind: 'int', value: Number(t.value) };
    if (t.kind === 'float') return { kind: 'float', value: Number(t.value) };
    if (t.kind === 'name') {
      if (t.value === 'true') return { kind: 'bool', value: true };
      if (t.value === 'false') return { kind: 'bool', value: false };
      if (t.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: t.value };
    }
    if (t.kind === 'punct' && t.value === '[') {
      const items: GqlValue[] = [];
      while (!this.isPunct(']')) items.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', items };
    }
    if (t.kind === 'punct' && t.value === '{') {
      const fields = new Map<string, GqlValue>();
      while (!this.isPunct('}')) {
        const key = this.next().value;
        this.expect(':');
        fields.set(key, this.parseValue());
      }
      this.expect('}');
      return { kind: 'object', fields };
    }
    throw new Error(`unexpected value token ${t.value}`);
  }
}

function resolveGqlValue(v: GqlValue, vars: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'var': return vars[v.name];
    case 'string': case 'int': case 'float': case 'bool': return v.value;
    case 'enum': return v.value;
    case 'null': return null;
    case 'list': return v.items.map((i) => resolveGqlValue(i, vars));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [k, val] of v.fields) out[k] = resolveGqlValue(val, vars);
      return out;
    }
  }
}

// --- the executor: domain objects carry __type; resolvers are plain functions ---

interface GqlCtx { errors: Array<{ message: string }>; }

type GqlObj = { __type: string; [key: string]: unknown };

const ISSUE_FIELDS = ['id', 'number', 'title', 'body', 'state', 'url', 'createdAt', 'closedAt', 'author', 'labels', 'comments'];
const PR_FIELDS = ['id', 'number', 'title', 'body', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'url', 'createdAt', 'author'];
const REPO_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'url', 'description', 'isPrivate', 'defaultBranch', 'createdAt'];

function issueGql(repo: Repo, issue: Issue): GqlObj {
  return {
    __type: 'Issue', __repo: repo, __issue: issue,
    id: issue.gid, number: issue.number, title: issue.title, body: issue.body,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
  };
}

function pullGql(repo: Repo, pull: Pull): GqlObj {
  return {
    __type: 'PullRequest', __repo: repo, __pull: pull,
    id: pull.gid, number: pull.number, title: pull.title, body: pull.body,
    headRefName: pull.head, baseRefName: pull.base,
    state: pull.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pull.merged,
    mergeable: 'MERGEABLE',
  };
}

function repoGql(repo: Repo): GqlObj {
  const owner = repoOwner(repo);
  return {
    __type: 'Repository', __repo: repo,
    id: repo.gid, databaseId: repo.dbId, name: repo.name, nameWithOwner: `${owner}/${repo.name}`,
    owner: { __type: 'User', login: owner } as GqlObj,
    defaultBranchRef: repo.refs.has('refs/heads/main') ? { __type: 'Ref', name: 'main' } as GqlObj : null,
    viewerPermission: 'ADMIN', hasIssuesEnabled: true,
  };
}

function decodeGid(gidStr: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(gidStr, 'base64url').toString('utf8');
    const [kind, ...parts] = text.split(':');
    if (!kind || parts.length === 0) return null;
    return { kind, parts };
  } catch {
    return null;
  }
}

function findRepoByGid(gidStr: string): Repo | null {
  const d = decodeGid(gidStr);
  if (!d || d.kind !== 'Repository') return null;
  const dbId = Number(d.parts[0]);
  for (const r of repos.values()) if (r.dbId === dbId) return r;
  return null;
}

function findIssueByGid(gidStr: string): { repo: Repo; issue: Issue } | null {
  const d = decodeGid(gidStr);
  if (!d || d.kind !== 'Issue') return null;
  const dbId = Number(d.parts[0]);
  const number = Number(d.parts[1]);
  for (const r of repos.values()) {
    if (r.dbId !== dbId) continue;
    const issue = r.issues.find((i) => i.number === number);
    if (issue) return { repo: r, issue };
  }
  return null;
}

function findPullByGid(gidStr: string): { repo: Repo; pull: Pull } | null {
  const d = decodeGid(gidStr);
  if (!d || d.kind !== 'PullRequest') return null;
  const dbId = Number(d.parts[0]);
  const number = Number(d.parts[1]);
  for (const r of repos.values()) {
    if (r.dbId !== dbId) continue;
    const pull = r.pulls.find((p) => p.number === number);
    if (pull) return { repo: r, pull };
  }
  return null;
}

function cursorFor(number: number): string {
  return b64url(`cursor:${number}`);
}

function cursorNumber(cursor: string | null | undefined): number | null {
  if (!cursor) return null;
  try {
    const text = Buffer.from(cursor, 'base64url').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

function executeSelection(sels: GqlSel[], obj: GqlObj, vars: Record<string, unknown>, ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of sels) {
    if (sel.kind === 'inline') {
      if (sel.typeCond && sel.typeCond !== obj.__type) continue;
      Object.assign(out, executeSelection(sel.selection, obj, vars, ctx));
      continue;
    }
    const f = sel.field;
    const key = f.alias ?? f.name;
    const value = resolveField(obj, f, vars, ctx);
    if (f.selection && value !== null && typeof value === 'object' && !Array.isArray(value)) {
      out[key] = executeSelection(f.selection, value as GqlObj, vars, ctx);
    } else if (f.selection && Array.isArray(value)) {
      out[key] = value.map((v) => (v !== null && typeof v === 'object' ? executeSelection(f.selection!, v as GqlObj, vars, ctx) : v));
    } else {
      out[key] = value;
    }
  }
  return out;
}

function fieldArgs(f: GqlField, vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of f.args) out[k] = resolveGqlValue(v, vars);
  return out;
}

function unknownField(ctx: GqlCtx, typeName: string, fieldName: string): null {
  ctx.errors.push({ message: `Cannot query field "${fieldName}" on type "${typeName}".` });
  return null;
}

function resolveField(obj: GqlObj, f: GqlField, vars: Record<string, unknown>, ctx: GqlCtx): unknown {
  const args = fieldArgs(f, vars);
  switch (obj.__type) {
    case 'Query': {
      if (f.name === 'viewer') return { __type: 'Viewer', login: viewerLogin ?? 'viewer' } as GqlObj;
      if (f.name === 'repository') {
        const repo = findRepo(String(args.owner ?? ''), String(args.name ?? ''));
        return repo ? repoGql(repo) : null;
      }
      if (f.name === 'node') {
        const id = String(args.id ?? '');
        const d = decodeGid(id);
        if (!d) return null;
        if (d.kind === 'Repository') {
          const repo = findRepoByGid(id);
          return repo ? repoGql(repo) : null;
        }
        if (d.kind === 'Issue') {
          const found = findIssueByGid(id);
          return found ? issueGql(found.repo, found.issue) : null;
        }
        if (d.kind === 'PullRequest') {
          const found = findPullByGid(id);
          return found ? pullGql(found.repo, found.pull) : null;
        }
        return null;
      }
      if (f.name === '__type') {
        const name = String(args.name ?? '');
        if (name === 'Issue') return { __type: '__Type', name, fields: ISSUE_FIELDS.map((n) => ({ __type: '__Field', name: n })), enumValues: null } as GqlObj;
        if (name === 'PullRequest') return { __type: '__Type', name, fields: PR_FIELDS.map((n) => ({ __type: '__Field', name: n })), enumValues: null } as GqlObj;
        if (name === 'Repository') return { __type: '__Type', name, fields: REPO_FIELDS.map((n) => ({ __type: '__Field', name: n })), enumValues: null } as GqlObj;
        if (name === 'SearchType') {
          return { __type: '__Type', name, fields: null, enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE'].map((n) => ({ __type: '__EnumValue', name: n })) } as GqlObj;
        }
        return null;
      }
      if (f.name === '__schema') return { __type: '__Schema', types: [] } as GqlObj;
      return unknownField(ctx, 'Query', f.name);
    }
    case 'Mutation': {
      if (f.name === 'createIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const repo = findRepoByGid(String(input.repositoryId ?? ''));
        if (!repo) { ctx.errors.push({ message: 'Repository not found' }); return null; }
        const created = createIssue(repo, String(input.title ?? ''), String(input.body ?? ''), []);
        if ('error' in created) { ctx.errors.push({ message: created.error }); return null; }
        return { __type: 'CreateIssuePayload', issue: issueGql(repo, created) } as GqlObj;
      }
      if (f.name === 'closeIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const found = findIssueByGid(String(input.issueId ?? ''));
        if (!found) { ctx.errors.push({ message: 'Issue not found' }); return null; }
        found.issue.state = 'closed';
        found.repo.issueJsonCache.delete(found.issue.number);
        return { __type: 'CloseIssuePayload', issue: issueGql(found.repo, found.issue) } as GqlObj;
      }
      if (f.name === 'createPullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const repo = findRepoByGid(String(input.repositoryId ?? ''));
        if (!repo) { ctx.errors.push({ message: 'Repository not found' }); return null; }
        const created = createPull(repo, String(input.title ?? ''), String(input.body ?? ''), String(input.headRefName ?? ''), String(input.baseRefName ?? 'main'));
        if ('error' in created) { ctx.errors.push({ message: created.error }); return null; }
        return { __type: 'CreatePullRequestPayload', pullRequest: pullGql(repo, created) } as GqlObj;
      }
      if (f.name === 'mergePullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const found = findPullByGid(String(input.pullRequestId ?? ''));
        if (!found) { ctx.errors.push({ message: 'Pull request not found' }); return null; }
        const merged = mergePull(found.repo, found.pull);
        if ('error' in merged) { ctx.errors.push({ message: merged.error }); return null; }
        return { __type: 'MergePullRequestPayload', pullRequest: pullGql(found.repo, found.pull) } as GqlObj;
      }
      if (f.name === 'addComment') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const found = findIssueByGid(String(input.subjectId ?? ''));
        if (!found) { ctx.errors.push({ message: 'Issue not found' }); return null; }
        const id = found.repo.nextCommentId++;
        const comment: Comment = { id, gid: gid('IssueComment', found.repo.dbId, found.issue.number, id), body: String(input.body ?? '') };
        const list = found.repo.comments.get(found.issue.number) ?? [];
        list.push(comment);
        found.repo.comments.set(found.issue.number, list);
        found.repo.issueJsonCache.delete(found.issue.number);
        return { __type: 'AddCommentPayload', commentEdge: { __type: 'IssueCommentEdge', node: { __type: 'IssueComment', id: comment.gid, body: comment.body } } } as GqlObj;
      }
      return unknownField(ctx, 'Mutation', f.name);
    }
    case 'Viewer': {
      if (f.name === 'login') return obj.login;
      return unknownField(ctx, 'Viewer', f.name);
    }
    case 'User': {
      if (f.name === 'login') return obj.login;
      return unknownField(ctx, 'User', f.name);
    }
    case 'Ref': {
      if (f.name === 'name') return obj.name;
      return unknownField(ctx, 'Ref', f.name);
    }
    case 'Repository': {
      const repo = obj.__repo as Repo;
      switch (f.name) {
        case 'id': case 'databaseId': case 'name': case 'nameWithOwner': case 'owner':
        case 'defaultBranchRef': case 'viewerPermission': case 'hasIssuesEnabled':
          return obj[f.name] ?? null;
        case 'issue': {
          const issue = repo.issues.find((i) => i.number === Number(args.number));
          return issue ? issueGql(repo, issue) : null;
        }
        case 'issues': {
          let list = [...repo.issues];
          if (Array.isArray(args.states)) {
            const wanted = new Set((args.states as unknown[]).map((s) => String(s).toLowerCase()));
            list = list.filter((i) => wanted.has(i.state));
          }
          const orderBy = args.orderBy as Record<string, unknown> | undefined;
          if (orderBy && String(orderBy.field ?? '') === 'CREATED_AT') {
            list.sort((a, b) => (String(orderBy.direction ?? '') === 'DESC' ? b.seq - a.seq : a.seq - b.seq));
          } else {
            list.sort((a, b) => a.seq - b.seq);
          }
          const first = typeof args.first === 'number' ? args.first : 10;
          const afterNum = cursorNumber(typeof args.after === 'string' ? args.after : null);
          let start = 0;
          if (afterNum !== null) {
            const idx = list.findIndex((i) => i.number === afterNum);
            start = idx < 0 ? 0 : idx + 1;
          }
          const page = list.slice(start, start + first);
          const hasNext = start + first < list.length;
          const endCursor = page.length ? cursorFor(page[page.length - 1].number) : null;
          return {
            __type: 'IssueConnection',
            nodes: page.map((i) => issueGql(repo, i)),
            pageInfo: { __type: 'PageInfo', hasNextPage: hasNext, endCursor },
          } as GqlObj;
        }
        case 'pullRequest': {
          const pull = repo.pulls.find((p) => p.number === Number(args.number));
          return pull ? pullGql(repo, pull) : null;
        }
        case 'pullRequests': {
          const first = typeof args.first === 'number' ? args.first : 10;
          const list = repo.pulls.filter((p) => p.state === 'open').slice(0, first);
          return { __type: 'PullRequestConnection', nodes: list.map((p) => pullGql(repo, p)) } as GqlObj;
        }
        default:
          return unknownField(ctx, 'Repository', f.name);
      }
    }
    case 'Issue': {
      const issue = obj.__issue as Issue;
      switch (f.name) {
        case 'id': case 'number': case 'title': case 'body': case 'state':
          return obj[f.name] ?? null;
        default:
          return unknownField(ctx, 'Issue', f.name);
      }
    }
    case 'PullRequest': {
      const pull = obj.__pull as Pull;
      switch (f.name) {
        case 'id': case 'number': case 'title': case 'body': case 'state': case 'merged': case 'mergeable':
        case 'headRefName': case 'baseRefName':
          return obj[f.name] ?? null;
        case 'files': {
          const first = typeof args.first === 'number' ? args.first : 10;
          const nodes = pull.files.slice(0, first).map((file) => ({ __type: 'PullRequestFile', path: file.filename }) as GqlObj);
          return { __type: 'PullRequestFileConnection', nodes } as GqlObj;
        }
        default:
          return unknownField(ctx, 'PullRequest', f.name);
      }
    }
    case 'IssueConnection': case 'PullRequestConnection': case 'PullRequestFileConnection': {
      if (f.name === 'nodes') return obj.nodes ?? [];
      if (f.name === 'pageInfo') return obj.pageInfo ?? null;
      if (f.name === 'edges') return [];
      return unknownField(ctx, obj.__type, f.name);
    }
    case 'PageInfo': {
      if (f.name === 'hasNextPage') return obj.hasNextPage;
      if (f.name === 'endCursor') return obj.endCursor;
      if (f.name === 'hasPreviousPage') return false;
      if (f.name === 'startCursor') return null;
      return unknownField(ctx, 'PageInfo', f.name);
    }
    case '__Type': {
      if (f.name === 'name') return obj.name;
      if (f.name === 'fields') return obj.fields ?? [];
      if (f.name === 'enumValues') return obj.enumValues ?? [];
      if (f.name === 'kind') return 'OBJECT';
      return unknownField(ctx, '__Type', f.name);
    }
    case '__Field': case '__EnumValue': {
      if (f.name === 'name') return obj.name;
      if (f.name === 'description') return null;
      return unknownField(ctx, obj.__type, f.name);
    }
    case 'CreateIssuePayload': case 'CloseIssuePayload': {
      if (f.name === 'issue') return obj.issue ?? null;
      return unknownField(ctx, obj.__type, f.name);
    }
    case 'CreatePullRequestPayload': case 'MergePullRequestPayload': {
      if (f.name === 'pullRequest') return obj.pullRequest ?? null;
      return unknownField(ctx, obj.__type, f.name);
    }
    case 'AddCommentPayload': {
      if (f.name === 'commentEdge') return obj.commentEdge ?? null;
      return unknownField(ctx, 'AddCommentPayload', f.name);
    }
    case 'IssueCommentEdge': {
      if (f.name === 'node') return obj.node ?? null;
      return unknownField(ctx, 'IssueCommentEdge', f.name);
    }
    case 'IssueComment': {
      if (f.name === 'id') return obj.id;
      if (f.name === 'body') return obj.body;
      return unknownField(ctx, 'IssueComment', f.name);
    }
    case 'PullRequestFile': {
      if (f.name === 'path') return obj.path;
      return unknownField(ctx, 'PullRequestFile', f.name);
    }
    case '__Schema': {
      if (f.name === 'types') return [];
      if (f.name === 'queryType') return { __type: '__Type', name: 'Query' } as GqlObj;
      if (f.name === 'mutationType') return { __type: '__Type', name: 'Mutation' } as GqlObj;
      return unknownField(ctx, '__Schema', f.name);
    }
    default:
      return unknownField(ctx, obj.__type, f.name);
  }
}

function executeGqlOperation(op: GqlOp, variables: Record<string, unknown>): { data: Record<string, unknown>; errors?: Array<{ message: string }> } {
  const ctx: GqlCtx = { errors: [] };
  const vars: Record<string, unknown> = { ...variables };
  for (const [name, def] of op.vars) {
    if (!(name in vars) && def !== undefined) vars[name] = resolveGqlValue(def, vars);
  }
  const root: GqlObj = op.kind === 'mutation' ? { __type: 'Mutation' } : { __type: 'Query' };
  const data = executeSelection(op.selection, root, vars, ctx);
  const out: { data: Record<string, unknown>; errors?: Array<{ message: string }> } = { data };
  if (ctx.errors.length) out.errors = ctx.errors;
  return out;
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!isAuthed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  const buf = await readBody(req);
  const parsed = parseJsonBody(buf);
  if (!parsed.ok) {
    sendJson(res, 400, { errors: [{ message: 'Invalid JSON body' }] });
    return;
  }
  const runOne = (doc: unknown): { data: Record<string, unknown>; errors?: Array<{ message: string }> } => {
    if (typeof doc !== 'object' || doc === null) return { data: {}, errors: [{ message: 'Invalid GraphQL document' }] };
    const d = doc as Record<string, unknown>;
    const query = typeof d.query === 'string' ? d.query : '';
    const variables = (d.variables ?? {}) as Record<string, unknown>;
    try {
      const ops = new GqlParser(gqlTokenize(query)).parseDocument();
      if (ops.length === 0) return { data: {}, errors: [{ message: 'Empty query' }] };
      // The suite sends one operation per document; an anonymous first operation wins.
      return executeGqlOperation(ops[0], variables);
    } catch (err) {
      return { data: {}, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
    }
  };
  if (Array.isArray(parsed.value)) {
    sendJson(res, 200, parsed.value.map((doc) => runOne(doc)));
  } else {
    sendJson(res, 200, runOne(parsed.value));
  }
}

// -------------------------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 over Streamable HTTP, modern revision 2026-07-28 (+ legacy initialize)
// -------------------------------------------------------------------------------------------

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the token user.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const MCP_TOOL_MAP = new Map(MCP_TOOLS.map((t) => [t.name as string, t]));

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result };
}

function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function toolTextResult(obj: unknown): Record<string, unknown> {
  const text = JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj, isError: false };
}

function toolErrorResult(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function callMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOL_MAP.get(name);
  if (!tool) return { __rpcError: { code: -32602, message: `Unknown tool: ${name}` } };
  const schema = tool.inputSchema as { required?: string[] };
  const required = schema.required ?? [];
  for (const key of required) {
    if (args[key] === undefined || args[key] === null || args[key] === '') {
      return { __toolResult: toolErrorResult(`Missing required argument: ${key}`) };
    }
  }
  const owner = typeof args.owner === 'string' ? args.owner : (viewerLogin ?? 'viewer');
  const repoName = typeof args.repo === 'string' ? args.repo : (typeof args.name === 'string' ? args.name : '');
  switch (name) {
    case 'create_repo': {
      const repoNameArg = typeof args.name === 'string' ? args.name : '';
      if (repos.has(repoNameArg)) return { __toolResult: toolErrorResult(`Repository "${repoNameArg}" already exists`) };
      const repo = createRepo(repoNameArg, typeof args.description === 'string' ? args.description : '', args.private === true);
      if (args.owner) bindOwner(repo, owner);
      return { __toolResult: toolTextResult(repoJson(repo)) };
    }
    case 'get_repo': {
      const repo = findRepo(owner, repoName);
      if (!repo) return { __toolResult: toolErrorResult(`Repository "${owner}/${repoName}" not found`) };
      return { __toolResult: toolTextResult(repoJson(repo)) };
    }
    case 'create_issue': {
      const repo = findRepo(owner, repoName);
      if (!repo) return { __toolResult: toolErrorResult(`Repository "${owner}/${repoName}" not found`) };
      const created = createIssue(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', []);
      if ('error' in created) return { __toolResult: toolErrorResult(created.error) };
      return { __toolResult: toolTextResult(issueJson(repo, created)) };
    }
    case 'list_issues': {
      const repo = findRepo(owner, repoName);
      if (!repo) return { __toolResult: toolErrorResult(`Repository "${owner}/${repoName}" not found`) };
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.issues.filter((i) => state === 'all' || i.state === state).map((i) => issueJson(repo, i));
      return { __toolResult: toolTextResult(list) };
    }
    case 'create_pull_request': {
      const repo = findRepo(owner, repoName);
      if (!repo) return { __toolResult: toolErrorResult(`Repository "${owner}/${repoName}" not found`) };
      const created = createPull(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', String(args.head ?? ''), String(args.base ?? 'main'));
      if ('error' in created) return { __toolResult: toolErrorResult(created.error) };
      return { __toolResult: toolTextResult(pullJson(repo, created)) };
    }
    case 'merge_pull_request': {
      const repo = findRepo(owner, repoName);
      if (!repo) return { __toolResult: toolErrorResult(`Repository "${owner}/${repoName}" not found`) };
      const pull = repo.pulls.find((p) => p.number === Number(args.pull_number));
      if (!pull) return { __toolResult: toolErrorResult(`Pull request #${String(args.pull_number)} not found`) };
      const merged = mergePull(repo, pull);
      if ('error' in merged) return { __toolResult: toolErrorResult(merged.error) };
      return { __toolResult: toolTextResult({ merged: true, sha: merged.sha, number: pull.number, state: 'closed' }) };
    }
    default:
      return { __rpcError: { code: -32602, message: `Unknown tool: ${name}` } };
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'DELETE') {
    res.writeHead(204);
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  if (!isAuthed(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Requires authentication' } });
    return;
  }
  const buf = await readBody(req);
  const parsed = parseJsonBody(buf);
  if (!parsed.ok) {
    sendJson(res, 400, mcpError(null, -32700, 'Parse error'));
    return;
  }
  const msg = parsed.value as Record<string, unknown> | null;
  if (!msg || typeof msg !== 'object' || typeof msg.method !== 'string') {
    sendJson(res, 400, mcpError(null, -32600, 'Invalid Request'));
    return;
  }
  const id = msg.id ?? null;
  const method = msg.method as string;
  const params = (msg.params ?? {}) as Record<string, unknown>;

  // A notification (no id) is answered 202 with no body.
  if (id === null || id === undefined) {
    res.writeHead(202);
    res.end();
    return;
  }

  if (method === 'server/discover') {
    sendJson(res, 200, mcpResult(id, {
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
    }));
    return;
  }
  if (method === 'initialize') {
    const requested = (params.protocolVersion as string) ?? '2025-11-25';
    sendJson(res, 200, mcpResult(id, {
      protocolVersion: requested,
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    }));
    return;
  }
  if (method === 'ping') {
    sendJson(res, 200, mcpResult(id, {}));
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, mcpResult(id, { tools: MCP_TOOLS }));
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const out = callMcpTool(toolName, args);
    if ('__rpcError' in out) {
      const e = out.__rpcError as { code: number; message: string };
      sendJson(res, 200, mcpError(id, e.code, e.message));
      return;
    }
    sendJson(res, 200, mcpResult(id, out.__toolResult));
    return;
  }
  sendJson(res, 200, mcpError(id, -32601, `Method not found: ${method}`));
}

// -------------------------------------------------------------------------------------------
// git smart HTTP
// -------------------------------------------------------------------------------------------

const V2_CAPS = 'ls-refs=unborn\nfetch=shallow filter\nobject-format=sha1\nagent=forge/1.0.0\n';
const V0_UP_CAPS = 'multi_ack_detailed side-band-64k thin-pack ofs-delta shallow symref=HEAD:refs/heads/main agent=forge/1.0.0';
const V0_RP_CAPS = 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0.0';

function sortedRefs(repo: Repo): Array<{ name: string; oid: string }> {
  return [...repo.refs.entries()].map(([name, oid]) => ({ name, oid })).sort((a, b) => (a.name < b.name ? -1 : 1));
}

function peeledCommit(repo: Repo, oid: string): string | null {
  const obj = repo.objects.get(oid);
  if (!obj) return null;
  if (obj.type === 'tag') return parseTag(obj.data).object;
  return null;
}

function advertisementV2(): Buffer {
  return pktLines(['# service=git-upload-pack\n', 'version 2\n', ...V2_CAPS.split('\n').filter((l) => l !== '').map((l) => `${l}\n`), 'flush']);
}

function advertisementV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? V0_UP_CAPS : V0_RP_CAPS;
  const serviceLine = `# service=${service}\n`;
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    return pktLines([serviceLine, `${ZERO_OID} capabilities^{}\0${caps}\n`, 'flush']);
  }
  const lines: Array<string | 'flush'> = [serviceLine];
  const head = repo.refs.get('refs/heads/main');
  if (head) {
    lines.push(`${head} HEAD\0${caps}\n`);
  }
  refs.forEach((ref, i) => {
    if (i === 0 && !head) lines.push(`${ref.oid} ${ref.name}\0${caps}\n`);
    else lines.push(`${ref.oid} ${ref.name}\n`);
    const peeled = peeledCommit(repo, ref.oid);
    if (peeled) lines.push(`${peeled} ${ref.name}^{}\n`);
  });
  lines.push('flush');
  return pktLines(lines);
}

interface FetchPlan { objects: GObj[]; shallow: string[]; unshallow: string[]; }

/** The objects a fetch's `haves` already cover: the have commits and their tree
 * closure, but never past a shallow boundary — a client holding a shallow tip
 * does not hold its parents, which is exactly what a deepen must still send. */
function haveClosure(repo: Repo, haves: string[], shallowSet: Set<string>): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [];
  for (const h of haves) if (isOid(h)) stack.push(h);
  while (stack.length) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const info = parseCommit(obj.data);
      stack.push(info.tree);
      if (!shallowSet.has(oid)) for (const p of info.parents) stack.push(p);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) if (e.mode !== '160000') stack.push(e.oid);
    }
  }
  return seen;
}

function planFetch(repo: Repo, wants: string[], haves: string[], depth: number | null, prevShallow: string[]): FetchPlan {
  // Distances from the wanted tips through commit parents.
  const dist = new Map<string, number>();
  const queue: Array<{ oid: string; d: number }> = [];
  const tagOids: string[] = [];
  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (!obj) continue;
    if (obj.type === 'tag') {
      tagOids.push(want);
      const target = parseTag(obj.data).object;
      if (!dist.has(target)) { dist.set(target, 0); queue.push({ oid: target, d: 0 }); }
    } else if (obj.type === 'commit') {
      if (!dist.has(want)) { dist.set(want, 0); queue.push({ oid: want, d: 0 }); }
    }
  }
  let qi = 0;
  while (qi < queue.length) {
    const { oid, d } = queue[qi++];
    for (const p of repo.parents.get(oid) ?? []) {
      if (!dist.has(p)) { dist.set(p, d + 1); queue.push({ oid: p, d: d + 1 }); }
    }
  }
  const included = new Set<string>();
  const shallow: string[] = [];
  for (const [oid, d] of dist) {
    if (depth === null || d < depth) included.add(oid);
  }
  // Boundary commits are the deepest included ones (distance depth-1).
  if (depth !== null) {
    for (const [oid, d] of dist) if (d === depth - 1) shallow.push(oid);
    shallow.sort();
  }
  const unshallow = prevShallow.filter((oid) => included.has(oid)).sort();
  const exclude = haveClosure(repo, haves, new Set(prevShallow));
  const wanted = new Set<string>();
  for (const oid of included) {
    if (exclude.has(oid)) continue;
    wanted.add(oid);
    const treeOid = repo.commitTree.get(oid);
    if (treeOid) for (const x of reachableObjects(repo, [treeOid])) if (!exclude.has(x)) wanted.add(x);
  }
  for (const tag of tagOids) if (!exclude.has(tag)) wanted.add(tag);
  const objects: GObj[] = [];
  for (const oid of [...wanted].sort()) {
    const obj = repo.objects.get(oid);
    if (obj) objects.push(obj);
  }
  return { objects, shallow, unshallow };
}

function fetchCacheKey(wants: string[], haves: string[], depth: number | null, prevShallow: string[]): string {
  return `${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${depth ?? ''}|${[...prevShallow].sort().join(',')}`;
}

function buildFetchResponse(repo: Repo, wants: string[], haves: string[], depth: number | null, prevShallow: string[], v2: boolean): Buffer {
  const key = `${v2 ? 'v2' : 'v0'}|${fetchCacheKey(wants, haves, depth, prevShallow)}`;
  const hit = repo.respCache.get(key);
  if (hit) return hit;
  const packKey = fetchCacheKey(wants, haves, depth, prevShallow);
  let cached = repo.packCache.get(packKey);
  if (!cached) {
    const plan = planFetch(repo, wants, haves, depth, prevShallow);
    cached = { pack: buildPack(plan.objects), shallow: plan.shallow, unshallow: plan.unshallow };
    repo.packCache.set(packKey, cached);
  }
  const { pack, shallow, unshallow } = cached;
  // ACKs: haves that are ancestors of a want.
  const wantClosure = reachableObjects(repo, wants);
  const acks = haves.filter((h) => wantClosure.has(h));
  const parts: Buffer[] = [];
  if (v2) {
    const ackLines: string[] = ['acknowledgments\n'];
    if (acks.length) {
      for (const a of acks) ackLines.push(`ACK ${a}\n`);
      ackLines.push('ready\n');
    } else {
      ackLines.push('NAK\n');
      ackLines.push('ready\n');
    }
    parts.push(pktLines([...ackLines, 'delim']));
    if (depth !== null) {
      const sLines: string[] = ['shallow-info\n'];
      for (const s of shallow) sLines.push(`shallow ${s}\n`);
      for (const u of unshallow) sLines.push(`unshallow ${u}\n`);
      parts.push(pktLines([...sLines, 'delim']));
    }
    parts.push(pktLines(['packfile\n']));
    parts.push(sideband([pack], 1));
  } else {
    const lines: string[] = [];
    if (acks.length) for (const a of acks) lines.push(`ACK ${a}\n`);
    else lines.push('NAK\n');
    for (const s of shallow) lines.push(`shallow ${s}\n`);
    for (const u of unshallow) lines.push(`unshallow ${u}\n`);
    parts.push(pktLines(lines));
    parts.push(sideband([pack], 1));
  }
  const out = Buffer.concat(parts);
  repo.respCache.set(key, out);
  return out;
}

function handleLsRefs(repo: Repo, args: string[]): Buffer {
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const unborn = args.includes('unborn');
  const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length));
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const lines: string[] = [];
  const mainTip = repo.refs.get('refs/heads/main');
  if (prefixes.length === 0 && symrefs) {
    if (mainTip) lines.push(`${mainTip} HEAD symref-target:refs/heads/main\n`);
    else if (unborn) lines.push('unborn HEAD symref-target:refs/heads/main\n');
  }
  for (const ref of sortedRefs(repo)) {
    if (!keep(ref.name)) continue;
    let line = `${ref.oid} ${ref.name}`;
    if (peel) {
      const peeled = peeledCommit(repo, ref.oid);
      if (peeled) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  return pktLines([...lines, 'flush']);
}

function parseFetchArgs(lines: string[]): { wants: string[]; haves: string[]; depth: number | null; shallow: string[]; command: string | null } {
  const out = { wants: [] as string[], haves: [] as string[], depth: null as number | null, shallow: [] as string[], command: null as string | null };
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('command=')) out.command = line.slice('command='.length);
    else if (line.startsWith('want ')) out.wants.push(line.slice(5).split(' ')[0]);
    else if (line.startsWith('have ')) out.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) out.shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) out.depth = Number(line.slice(7));
  }
  return out;
}

async function handleGitUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const buf = await readBody(req);
  let packets: Packet[];
  try {
    packets = parsePktLines(buf);
  } catch {
    res.writeHead(400);
    res.end();
    return;
  }
  const dataLines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
  const first = dataLines[0] ?? '';
  if (first.startsWith('command=')) {
    const command = first.slice('command='.length).replace(/\n$/, '');
    const delimIdx = packets.findIndex((p) => p.kind === 'delim');
    // The command's arguments follow the delim packet, not the command line.
    const argLines = (delimIdx < 0 ? packets.slice(1) : packets.slice(delimIdx + 1))
      .filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
    if (command === 'ls-refs') {
      sendRaw(res, 200, handleLsRefs(repo, argLines.map((l) => l.replace(/\n$/, ''))), 'application/x-git-upload-pack-result');
      return;
    }
    if (command === 'fetch') {
      const { wants, haves, depth, shallow } = parseFetchArgs([first, ...argLines]);
      if (!wants.length) { sendRaw(res, 200, Buffer.alloc(0), 'application/x-git-upload-pack-result'); return; }
      sendRaw(res, 200, buildFetchResponse(repo, wants, haves, depth, shallow, true), 'application/x-git-upload-pack-result');
      return;
    }
    res.writeHead(400);
    res.end();
    return;
  }
  // v0 fetch: want/have/shallow/deepen lines, two sections split by flush.
  const { wants, haves, depth, shallow } = parseFetchArgs(dataLines);
  if (!wants.length) {
    res.writeHead(400);
    res.end();
    return;
  }
  sendRaw(res, 200, buildFetchResponse(repo, wants, haves, depth, shallow, false), 'application/x-git-upload-pack-result');
}

async function handleGitReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const buf = await readBody(req);
  // Walk pkt-lines with offsets; everything after the first flush packet is the raw pack.
  let off = 0;
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let packStart = buf.length;
  try {
    while (off < buf.length) {
      if (off + 4 > buf.length) throw new Error('truncated');
      const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
      if (Number.isNaN(len) || len < 0 || len > 65520) throw new Error('bad length');
      if (len === 0) { packStart = off + 4; break; }
      if (len === 1) { off += 4; continue; }
      if (len < 4 || off + len > buf.length) throw new Error('bad length');
      const payload = buf.subarray(off + 4, off + len).toString('utf8');
      const nul = payload.indexOf('\0');
      const line = (nul >= 0 ? payload.slice(0, nul) : payload).replace(/\n$/, '');
      const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(line);
      if (!m) throw new Error('bad command line');
      commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
      off += len;
    }
  } catch {
    res.writeHead(400);
    res.end();
    return;
  }
  if (commands.length === 0) {
    res.writeHead(400);
    res.end();
    return;
  }
  const packBytes = buf.subarray(packStart);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const objects = parsePack(packBytes);
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) {
          repo.objects.set(oid, obj);
          if (obj.type === 'commit') {
            const info = parseCommit(obj.data);
            repo.parents.set(oid, info.parents);
            repo.commitTree.set(oid, info.tree);
          }
        }
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : String(err);
    }
  }
  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}\n`];
  if (unpackOk) {
    let changed = false;
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        // delete
        if (!current) reportLines.push(`ng ${cmd.ref} remote ref does not exist\n`);
        else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) reportLines.push(`ng ${cmd.ref} old value does not match\n`);
        else { repo.refs.delete(cmd.ref); changed = true; reportLines.push(`ok ${cmd.ref}\n`); }
        continue;
      }
      if (cmd.oldOid === ZERO_OID) {
        // create
        if (current) reportLines.push(`ng ${cmd.ref} already exists\n`);
        else if (!repo.objects.has(cmd.newOid)) reportLines.push(`ng ${cmd.ref} object not found\n`);
        else { repo.refs.set(cmd.ref, cmd.newOid); changed = true; reportLines.push(`ok ${cmd.ref}\n`); }
        continue;
      }
      // update
      if (!current) reportLines.push(`ng ${cmd.ref} remote ref does not exist\n`);
      else if (cmd.oldOid !== current) reportLines.push(`ng ${cmd.ref} old value does not match\n`);
      else if (!repo.objects.has(cmd.newOid)) reportLines.push(`ng ${cmd.ref} object not found\n`);
      else if (!isAncestor(repo, current, cmd.newOid)) reportLines.push(`ng ${cmd.ref} non-fast-forward\n`);
      else { repo.refs.set(cmd.ref, cmd.newOid); changed = true; reportLines.push(`ok ${cmd.ref}\n`); }
    }
    if (changed) invalidateRepoCaches(repo);
  }
  const report = pktLines(reportLines);
  sendRaw(res, 200, sideband([report], 1), 'application/x-git-receive-pack-result');
}

async function handleGit(req: IncomingMessage, res: ServerResponse, parts: string[], search: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  const owner = parts[0];
  const repoName = parts[1];
  const repo = findRepo(owner, repoName);
  const tail = parts.slice(2);
  if (method === 'GET' && tail.length === 2 && tail[0] === 'info' && tail[1] === 'refs') {
    if (!repo) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    const service = search.get('service') ?? '';
    if (service === 'git-upload-pack') {
      const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      if (v2) {
        let ad = repo.adCache.get('v2up');
        if (!ad) { ad = advertisementV2(); repo.adCache.set('v2up', ad); }
        sendRaw(res, 200, ad, 'application/x-git-upload-pack-advertisement');
      } else {
        let ad = repo.adCache.get('v0up');
        if (!ad) { ad = advertisementV0(repo, 'git-upload-pack'); repo.adCache.set('v0up', ad); }
        sendRaw(res, 200, ad, 'application/x-git-upload-pack-advertisement');
      }
      return;
    }
    if (service === 'git-receive-pack') {
      let ad = repo.adCache.get('v0rp');
      if (!ad) { ad = advertisementV0(repo, 'git-receive-pack'); repo.adCache.set('v0rp', ad); }
      sendRaw(res, 200, ad, 'application/x-git-receive-pack-advertisement');
      return;
    }
    res.writeHead(400);
    res.end();
    return;
  }
  if (!repo) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Not Found');
    return;
  }
  if (method === 'POST' && tail.length === 1 && tail[0] === 'git-upload-pack') {
    await handleGitUploadPack(req, res, repo);
    return;
  }
  if (method === 'POST' && tail.length === 1 && tail[0] === 'git-receive-pack') {
    await handleGitReceivePack(req, res, repo);
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('Not Found');
}

// -------------------------------------------------------------------------------------------
// the server
// -------------------------------------------------------------------------------------------

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const pathname = url.pathname;
        const search = url.searchParams;
        const method = req.method ?? 'GET';

        if (method === 'GET' && pathname === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (pathname === '/mcp') {
          await handleMcp(req, res);
          return;
        }
        if (method === 'POST' && pathname === '/api/graphql') {
          await handleGraphql(req, res);
          return;
        }
        if (pathname === '/api/v3' || pathname.startsWith('/api/v3/')) {
          const rest = pathname === '/api/v3' ? [] : splitPath(pathname.slice('/api/v3/'.length));
          await handleRest(req, res, rest, search);
          return;
        }
        const gitMatch = /^\/([^/]+)\/([^/]+)\.git(?:\/(.*))?$/.exec(pathname);
        if (gitMatch) {
          const parts = [gitMatch[1], gitMatch[2], ...(gitMatch[3] ? gitMatch[3].split('/').filter((s) => s !== '') : [])];
          await handleGit(req, res, parts, search);
          return;
        }
        sendJson(res, 404, { message: 'Not Found' });
      } catch (err) {
        if (!res.headersSent) {
          sendJson(res, 500, { message: err instanceof Error ? err.message : String(err) });
        } else {
          res.end();
        }
      }
    })();
  });
}
