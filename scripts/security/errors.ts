export type ErrorCode =
  | 'INVALID_INPUT'
  | 'AUTH_FAILED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'API_UNSUPPORTED'
  | 'API_ERROR'
  | 'CONFLICT'
  | 'SYNTAX_FAILED'
  | 'RELOAD_FAILED'
  | 'VERIFY_FAILED'
  | 'ROLLBACK_FAILED'
  | 'NETWORK'
  | 'TIMEOUT'
  | 'DEPENDENCY_MISSING'
  | 'TARGET_MISMATCH';
export class PanelError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'PanelError';
  }
}
export function requireInput(condition: unknown, message: string): asserts condition {
  if (!condition) throw new PanelError('INVALID_INPUT', message);
}
export function classify(status: number, message = ''): ErrorCode {
  if (status === 401) return 'AUTH_FAILED';
  if (status === 403) return 'FORBIDDEN';
  if (status === 404) return 'NOT_FOUND';
  if (status === 405 || status === 501) return 'API_UNSUPPORTED';
  if (status === 409) return 'CONFLICT';
  if (/reload|restart failed|重载|重启失败/i.test(message)) return 'RELOAD_FAILED';
  if (/nginx.*(emerg|test failed)|syntax|语法/i.test(message)) return 'SYNTAX_FAILED';
  return 'API_ERROR';
}
