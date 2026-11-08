import { journalBackup, journalAudit } from './journal.js';
import { createHash } from 'node:crypto';
import { PanelError, requireInput } from './errors.js';

export const sha256 = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
export const ABSENT_SHA256 = sha256('1panel-skills:absent:v1');
export const digest = (value: string | null) => (value === null ? ABSENT_SHA256 : sha256(value));
export interface WriteIntent {
  apply?: boolean;
  confirm?: boolean;
  expectedSha256?: string;
  acknowledgeNonAtomic?: boolean;
}
export interface Resource {
  id: string;
  target: unknown;
  read(): Promise<string | null>;
  write(content: string | null): Promise<void>;
  recoverySnapshot?: string;
  guardRollback?(): Promise<void>;
  ownsIntermediate?(content: string | null): boolean;
  validate?(content: string | null): void;
  verify?(content: string | null): Promise<void>;
}
export interface Audit {
  at: string;
  resource: string;
  target: unknown;
  beforeSha256: string;
  afterSha256: string;
  preview: ReturnType<typeof previewDiff>;
  result: string;
  validation: string;
  runtime: string;
}
export function previewDiff(before: string | null, after: string | null) {
  const a = (before ?? '').split('\n'),
    b = (after ?? '').split('\n');
  let prefix = 0,
    suffix = 0;
  while (prefix < Math.min(a.length, b.length) && a[prefix] === b[prefix]) prefix++;
  while (
    suffix < Math.min(a.length, b.length) - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
  )
    suffix++;
  // Deliberately structural: full proposed files are reviewed locally, never copied into audit logs.
  return {
    startLine: prefix + 1,
    removedLines: a.length - prefix - suffix,
    addedLines: b.length - prefix - suffix,
    contents: 'REDACTED',
    beforeBytes: Buffer.byteLength(before ?? ''),
    afterBytes: Buffer.byteLength(after ?? ''),
  };
}
export async function safeWrite(
  resource: Resource,
  content: string | null,
  intent: WriteIntent = {},
) {
  requireInput(
    intent.apply === undefined || typeof intent.apply === 'boolean',
    'apply must be boolean',
  );
  resource.validate?.(content);
  const before = await resource.read();
  const beforeSha256 = digest(before),
    afterSha256 = digest(content);
  const audit: Audit = {
    at: new Date().toISOString(),
    resource: resource.id,
    target: resource.target,
    beforeSha256,
    afterSha256,
    preview: previewDiff(before, content),
    result: 'DRY_RUN',
    validation: 'LOCAL_ONLY',
    runtime: 'NOT_TESTED',
  };
  if (!intent.apply) return { status: 'DRY_RUN', expectedSha256: beforeSha256, afterSha256, audit };
  requireInput(
    intent.confirm === true && /^[a-f0-9]{64}$/.test(intent.expectedSha256 ?? ''),
    'Apply requires confirm:true and expectedSha256',
  );
  // Idempotent replay with original expected hash is allowed only if desired bytes already exist.
  if (beforeSha256 === afterSha256) {
    audit.result = 'UNCHANGED';
    return { status: 'UNCHANGED', expectedSha256: beforeSha256, afterSha256, audit };
  }
  if (intent.expectedSha256 !== beforeSha256)
    throw new PanelError('CONFLICT', 'Baseline changed; create a new plan', {
      audit: { ...audit, result: 'CONFLICT' },
    });
  if (digest(await resource.read()) !== beforeSha256)
    throw new PanelError('CONFLICT', 'Concurrent edit before write', {
      audit: { ...audit, result: 'CONFLICT' },
    });
  const backupPath = await journalBackup(
    resource.id,
    resource.target,
    resource.recoverySnapshot ?? before,
  );
  try {
    try {
      await resource.write(content);
    } catch (err) {
      // Timeout/disconnect can occur after the server committed. Never blindly retry.
      if (
        !(err instanceof PanelError) ||
        !['TIMEOUT', 'NETWORK'].includes(err.code) ||
        digest(await resource.read()) !== afterSha256
      )
        throw err;
    }
    if (digest(await resource.read()) !== afterSha256)
      throw new PanelError('VERIFY_FAILED', 'Read-back differs from proposed bytes');
    await resource.verify?.(content);
    audit.result = 'APPLIED';
    await journalAudit(backupPath, audit);
    return { status: 'APPLIED', expectedSha256: beforeSha256, afterSha256, backupPath, audit };
  } catch (original) {
    try {
      const currentContent = await resource.read();
      const current = digest(currentContent);
      if (current !== beforeSha256) {
        // A third-party edit must never be overwritten by automatic compensation.
        if (current !== afterSha256 && !resource.ownsIntermediate?.(currentContent))
          throw new PanelError('CONFLICT', 'Unknown concurrent state; manual recovery required');
        await resource.guardRollback?.();
        await resource.write(before);
      }
      if (digest(await resource.read()) !== beforeSha256)
        throw new PanelError('VERIFY_FAILED', 'Recovery read-back mismatch');
      await resource.verify?.(before);
    } catch (rollback) {
      await journalAudit(backupPath, { ...audit, result: 'ROLLBACK_FAILED' }).catch(
        () => undefined,
      );
      throw new PanelError(
        'ROLLBACK_FAILED',
        'Recovery failed; stop writes and restore the protected pre-change backup after checking current state',
        {
          backupPath,
          originalCode: original instanceof PanelError ? original.code : 'API_ERROR',
          rollbackCode: rollback instanceof PanelError ? rollback.code : 'API_ERROR',
          audit: { ...audit, result: 'ROLLBACK_FAILED' },
        },
      );
    }
    await journalAudit(backupPath, { ...audit, result: 'ROLLED_BACK' });
    throw new PanelError(
      original instanceof PanelError ? original.code : 'API_ERROR',
      'Change failed; original bytes restored and checked',
      { backupPath, audit: { ...audit, result: 'ROLLED_BACK' } },
    );
  }
}
