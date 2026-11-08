import { mkdir, open, lstat } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { requireInput } from './errors.js';
import { redact } from './redaction.js';
export async function journalBackup(resource, target, content) {
    const root = path.resolve(process.env.ONEPANEL_STATE_DIR || path.join(os.homedir(), '.local/state/1panel-skills'));
    await mkdir(root, { recursive: true, mode: 0o700 });
    const info = await lstat(root);
    requireInput(!info.isSymbolicLink() &&
        info.isDirectory() &&
        (info.mode & 0o077) === 0 &&
        (!process.getuid || info.uid === process.getuid()), 'Journal directory must be owned, private (0700) and not a symlink');
    const backup = path.join(root, randomUUID() + '.backup.json');
    const file = await open(backup, 'wx', 0o600);
    try {
        await file.writeFile(JSON.stringify({ at: new Date().toISOString(), resource, target, content }));
        await file.sync();
    }
    finally {
        await file.close();
    }
    return backup;
}
export async function journalAudit(backup, audit) {
    const file = await open(backup + '.audit.json', 'wx', 0o600);
    try {
        await file.writeFile(JSON.stringify(redact(audit), null, 2));
        await file.sync();
    }
    finally {
        await file.close();
    }
}
