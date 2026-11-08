import { X509Certificate, createHash } from 'node:crypto';
import { checkContent } from './discovery.js';
import { requireInput, PanelError } from './errors.js';
export function normalizeFingerprints(values) {
    requireInput(Array.isArray(values) && values.length <= 512, 'At most 512 SHA-256 fingerprints');
    return [
        ...new Set(values.map((v) => {
            requireInput(typeof v === 'string' &&
                (/^[a-fA-F0-9]{64}$/.test(v) || /^(?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2}$/.test(v)), 'Invalid SHA-256 fingerprint');
            return v.replace(/:/g, '').toUpperCase();
        })),
    ].sort();
}
export function certificateFingerprint(pem) {
    return createHash('sha256').update(new X509Certificate(pem).raw).digest('hex').toUpperCase();
}
export function parseCABundle(pem, now = Date.now()) {
    checkContent(pem);
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
    requireInput(blocks.length > 0 &&
        blocks.length <= 32 &&
        pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim() ===
            '', 'Expected 1–32 PEM CA certificates with no other material');
    const certificates = [
        ...new Map(blocks.map((block) => {
            let cert;
            try {
                cert = new X509Certificate(block);
            }
            catch {
                throw new PanelError('INVALID_INPUT', 'Invalid X.509 CA PEM');
            }
            requireInput(cert.ca, 'End-entity certificates cannot be trusted as CAs');
            requireInput(Date.parse(cert.validFrom) <= now && now < Date.parse(cert.validTo), 'CA is expired or not yet valid');
            return [certificateFingerprint(block), cert];
        })).values(),
    ];
    for (const cert of certificates) {
        let current = cert;
        let subordinateCAs = 0;
        const seen = new Set();
        for (;;) {
            const limit = pathLengthLimit(current);
            requireInput(limit === undefined || subordinateCAs <= limit, 'CA path length constraint exceeded');
            const fingerprint = certificateFingerprint(current.toString());
            requireInput(!seen.has(fingerprint), 'CA chain contains a cycle');
            seen.add(fingerprint);
            if (current.subject === current.issuer &&
                current.checkIssued(current) &&
                current.verify(current.publicKey))
                break;
            const issuers = certificates.filter((parent) => parent !== current && current.checkIssued(parent) && current.verify(parent.publicKey));
            requireInput(issuers.length === 1, 'Each intermediate needs one valid issuer in the bundle');
            if (current.subject !== current.issuer)
                subordinateCAs++;
            current = issuers[0];
        }
    }
    const sorted = certificates.sort((a, b) => a.fingerprint256.localeCompare(b.fingerprint256));
    return {
        bundle: sorted.map((c) => c.toString().trim() + '\n').join(''),
        certificates: sorted.map((c) => ({
            fingerprint: certificateFingerprint(c.toString()),
            subject: c.subject,
            issuer: c.issuer,
            validTo: c.validTo,
        })),
        fingerprints: sorted.map((c) => certificateFingerprint(c.toString())),
    };
}
// Read only BasicConstraints.pathLenConstraint from the already parsed X.509 DER.
// Node validates CA/issuer/signatures; its X509Certificate API does not expose pathLen.
function pathLengthLimit(cert) {
    const bytes = cert.raw;
    function node(offset, limit = bytes.length) {
        requireInput(offset + 2 <= limit, 'Truncated certificate DER');
        const tag = bytes[offset++];
        let length = bytes[offset++];
        if (length & 128) {
            const count = length & 127;
            requireInput(count > 0 && count <= 4 && offset + count <= limit, 'Invalid certificate DER length');
            length = 0;
            for (let n = 0; n < count; n++)
                length = length * 256 + bytes[offset++];
        }
        requireInput(offset + length <= limit, 'Certificate DER length exceeds boundary');
        return { tag, start: offset, end: offset + length };
    }
    function children(parent) {
        const out = [];
        let offset = parent.start;
        while (offset < parent.end) {
            const child = node(offset, parent.end);
            out.push(child);
            offset = child.end;
        }
        return out;
    }
    const certificate = node(0);
    const tbs = children(certificate)[0];
    const extensionContainer = children(tbs).find((n) => n.tag === 0xa3);
    if (!extensionContainer)
        return undefined;
    const extensions = children(children(extensionContainer)[0]);
    for (const extension of extensions) {
        const fields = children(extension);
        if (bytes.subarray(fields[0].start, fields[0].end).toString('hex') !== '551d13')
            continue;
        const octets = fields.at(-1);
        requireInput(octets.tag === 4, 'Invalid BasicConstraints encoding');
        const constraints = node(octets.start, octets.end);
        const integer = children(constraints).find((n) => n.tag === 2);
        if (!integer)
            return undefined;
        requireInput(integer.end > integer.start &&
            !(bytes[integer.start] & 128) &&
            integer.end - integer.start <= 4, 'Invalid CA path length');
        let value = 0;
        for (let i = integer.start; i < integer.end; i++)
            value = value * 256 + bytes[i];
        return value;
    }
    return undefined;
}
