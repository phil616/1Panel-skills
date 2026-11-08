// Audit previews never contain credentials, certificate bodies or arbitrary config lines.
export function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k,
        /api[_-]?key|private[_-]?key|access[_-]?key|eabHmacKey|^key$|token|secret|password|^pem$|^certificate$|caBundle|siteContent|reviewDiff|rawBody|^content$|dockerCompose|^env$|shell/i.test(
          k,
        )
          ? '[REDACTED]'
          : redact(v),
      ]),
    );
  if (typeof value !== 'string') return value;
  return value
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '[REDACTED PEM]')
    .replace(/((?:password|token|api[_-]?key|secret)\s*[:=]\s*)[^\s;,]+/gi, '$1[REDACTED]');
}
