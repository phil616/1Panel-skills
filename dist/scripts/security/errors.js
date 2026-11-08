export class PanelError extends Error {
    code;
    details;
    constructor(code, message, details) {
        super(message);
        this.code = code;
        this.details = details;
        this.name = 'PanelError';
    }
}
export function requireInput(condition, message) {
    if (!condition)
        throw new PanelError('INVALID_INPUT', message);
}
export function classify(status, message = '') {
    if (status === 401)
        return 'AUTH_FAILED';
    if (status === 403)
        return 'FORBIDDEN';
    if (status === 404)
        return 'NOT_FOUND';
    if (status === 405 || status === 501)
        return 'API_UNSUPPORTED';
    if (status === 409)
        return 'CONFLICT';
    if (/reload|restart failed|重载|重启失败/i.test(message))
        return 'RELOAD_FAILED';
    if (/nginx.*(emerg|test failed)|syntax|语法/i.test(message))
        return 'SYNTAX_FAILED';
    return 'API_ERROR';
}
