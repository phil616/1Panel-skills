import { createHash, createHmac, randomBytes } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { classify, PanelError, requireInput } from './security/errors.js';
export function signHeaders(apiKey, timestamp, version = 'md5', keyId) {
    requireInput(version === 'md5' || version === 'hmac-sha256', 'Unsupported signature version; no automatic downgrade');
    requireInput(/^\d+$/.test(timestamp), 'Timestamp must be Unix seconds');
    const token = version === 'md5'
        ? createHash('md5').update(`1panel${apiKey}${timestamp}`).digest('hex')
        : createHmac('sha256', apiKey).update(`1panel:${timestamp}`).digest('hex');
    return {
        '1Panel-Token': token,
        '1Panel-Timestamp': timestamp,
        '1Panel-Signature-Version': version,
        ...(keyId ? { '1Panel-Key-ID': keyId } : {}),
    };
}
export class OnePanelClient {
    targetOrigin;
    config;
    constructor(config) {
        const url = new URL(config.baseUrl);
        requireInput(['http:', 'https:'].includes(url.protocol) &&
            !url.username &&
            !url.password &&
            !url.search &&
            !url.hash &&
            url.pathname === '/', 'baseUrl must be an HTTP(S) origin without credentials');
        requireInput(config.apiKey &&
            Number.isFinite(config.timeoutMs ?? 30000) &&
            (config.timeoutMs ?? 30000) > 0, 'API key and positive timeout required');
        requireInput(!config.signatureVersion || ['md5', 'hmac-sha256'].includes(config.signatureVersion), 'Unknown signature version');
        this.targetOrigin = url.origin;
        this.config = config;
    }
    static fromEnv(env) {
        return new OnePanelClient({
            baseUrl: env.ONEPANEL_BASE_URL?.trim() ?? '',
            apiKey: env.ONEPANEL_API_KEY?.trim() ?? '',
            timeoutMs: Number(env.ONEPANEL_TIMEOUT_MS || 30000),
            skipTlsVerify: /^(1|true|yes)$/i.test(env.ONEPANEL_SKIP_TLS_VERIFY || ''),
            signatureVersion: (env.ONEPANEL_SIGNATURE_VERSION || 'md5'),
            keyId: env.ONEPANEL_KEY_ID,
        });
    }
    async request(options) {
        const retries = options.method === 'GET' || options.readOnly === true
            ? Math.min(this.config.readRetries ?? 1, 2)
            : 0;
        for (let n = 0;; n++) {
            try {
                return await this.once(options);
            }
            catch (err) {
                if (n >= retries ||
                    !(err instanceof PanelError) ||
                    !['NETWORK', 'TIMEOUT'].includes(err.code))
                    throw err;
            }
        }
    }
    async once(options) {
        requireInput(/^\/api\/v2\/[A-Za-z0-9_./:-]*$/.test(options.path) &&
            !options.path.split('/').includes('..'), 'Invalid API path');
        const url = new URL(options.path, this.targetOrigin);
        for (const [key, value] of Object.entries(options.query ?? {}))
            if (value !== null && value !== undefined && value !== '')
                url.searchParams.set(key, String(value));
        if (options.operateNode)
            url.searchParams.set('operateNode', options.operateNode);
        let body;
        let contentType = 'application/json';
        if (options.multipart) {
            requireInput(options.body === undefined, 'Use JSON or multipart, not both');
            const boundary = 'onepanel-' + randomBytes(24).toString('hex');
            const { fields, file } = options.multipart;
            requireInput(/^[A-Za-z0-9_.-]+$/.test(file.name), 'Invalid upload filename');
            const chunks = [];
            for (const [name, value] of Object.entries(fields)) {
                requireInput(/^[A-Za-z]+$/.test(name), 'Invalid form field');
                chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
            }
            requireInput(!file.contentType || /^[\w/+.-]+$/.test(file.contentType), 'Invalid MIME type');
            chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${file.name}"\r\nContent-Type: ${file.contentType || 'application/octet-stream'}\r\n\r\n`), file.content, Buffer.from(`\r\n--${boundary}--\r\n`));
            body = Buffer.concat(chunks);
            contentType = `multipart/form-data; boundary=${boundary}`;
        }
        else if (options.body !== undefined)
            body = Buffer.from(JSON.stringify(options.body));
        requireInput((body?.length ?? 0) <= 2 * 1024 * 1024, 'Request exceeds 2 MiB');
        const timestamp = String(Math.floor((this.config.now?.() ?? Date.now()) / 1000));
        const headers = {
            ...this.config.defaultHeaders,
            Accept: 'application/json, text/plain, text/event-stream',
            'Content-Type': contentType,
            'Content-Length': String(body?.length ?? 0),
            ...signHeaders(this.config.apiKey, timestamp, this.config.signatureVersion, this.config.keyId),
        };
        return new Promise((resolve, reject) => {
            const isHttps = url.protocol === 'https:';
            const request = (isHttps ? https : http).request(url, {
                method: options.method,
                headers,
                rejectUnauthorized: !this.config.skipTlsVerify,
                timeout: this.config.timeoutMs ?? 30000,
            }, (response) => {
                const chunks = [];
                let size = 0;
                response.on('data', (chunk) => {
                    size += chunk.length;
                    if (size > 8 * 1024 * 1024)
                        response.destroy(new PanelError('API_ERROR', 'Response exceeds 8 MiB'));
                    else
                        chunks.push(chunk);
                });
                response.on('aborted', () => reject(new PanelError('NETWORK', 'Response interrupted; writes are never automatically retried')));
                response.on('error', () => reject(new PanelError('NETWORK', 'Response interrupted')));
                response.on('end', () => {
                    const rawBody = Buffer.concat(chunks).toString('utf8');
                    const status = response.statusCode ?? 0;
                    const normalizedHeaders = Object.fromEntries(Object.entries(response.headers).map(([k, v]) => [
                        k,
                        Array.isArray(v) ? v.join(', ') : String(v ?? ''),
                    ]));
                    let data;
                    try {
                        data = JSON.parse(rawBody);
                    }
                    catch {
                        if (status >= 400) {
                            reject(new PanelError(classify(status), `1Panel HTTP ${status}`));
                            return;
                        }
                        if (normalizedHeaders['content-type']?.includes('json')) {
                            reject(new PanelError('API_ERROR', 'Invalid JSON response'));
                            return;
                        }
                        data = rawBody;
                    }
                    const business = typeof data?.code === 'number' ? data.code : 200;
                    if (status >= 400 || (business !== 200 && business !== 0)) {
                        const code = classify(status >= 400 ? status : business, String(data?.message ?? ''));
                        const serverTime = Date.parse(normalizedHeaders.date ?? '');
                        reject(new PanelError(code, `1Panel rejected request (${status}/${business}); check server operation logs`, {
                            status,
                            business,
                            clockSkewSeconds: Number.isFinite(serverTime)
                                ? Math.round((serverTime - Number(timestamp) * 1000) / 1000)
                                : undefined,
                        }));
                        return;
                    }
                    resolve({ status, headers: normalizedHeaders, data: data, rawBody });
                });
            });
            request.on('timeout', () => request.destroy(new PanelError('TIMEOUT', '1Panel request timed out; write outcome may be unknown')));
            request.on('error', (err) => reject(err instanceof PanelError
                ? err
                : new PanelError('NETWORK', '1Panel connection failed; check target and TLS trust')));
            if (body)
                request.write(body);
            request.end();
        });
    }
}
