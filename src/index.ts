import * as AppAuth from 'react-native-app-auth';
import * as Keychain from 'react-native-keychain';

export class YeboIDError extends Error {
  constructor(public readonly code: string, public readonly status?: number) { super(`YeboID: ${code}`); this.name = 'YeboIDError'; }
}
export interface Tokens { accessToken: string; refreshToken?: string; expiresAt: string; }
export interface TokenStore { load(): Promise<Tokens | null>; save(tokens: Tokens): Promise<void>; clear(): Promise<void>; }
export interface UserInfo { sub: string; preferred_username?: string; [claim: string]: unknown; }

/** One service per issuer/client. Secure storage is mandatory; never use AsyncStorage. */
export class KeychainTokenStore implements TokenStore {
  constructor(private readonly service: string) {}
  async load(): Promise<Tokens | null> {
    const value = await Keychain.getGenericPassword({ service: this.service });
    if (value === false) return null;
    const data: Tokens = JSON.parse(value.password);
    validateTokens(data);
    return data;
  }
  async save(tokens: Tokens): Promise<void> {
    validateTokens(tokens);
    const result = await Keychain.setGenericPassword('yeboid', JSON.stringify(tokens), {
      service: this.service, accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
    if (!result) throw new YeboIDError('storage_failed');
  }
  async clear(): Promise<void> {
    await Keychain.resetGenericPassword({ service: this.service });
    if (await this.load()) throw new YeboIDError('storage_delete_failed');
  }
}

function validateTokens(data: Tokens): void {
  if (!data || typeof data.accessToken !== 'string' || !data.accessToken || !Number.isFinite(Date.parse(data.expiresAt)) ||
      (data.refreshToken !== undefined && (typeof data.refreshToken !== 'string' || !data.refreshToken))) throw new YeboIDError('invalid_tokens');
}
function https(value: unknown): string {
  if (typeof value !== 'string') throw new YeboIDError('invalid_endpoint');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new YeboIDError('invalid_endpoint');
  return value;
}

export interface Options { clientId: string; redirectUrl: string; issuer?: string; scopes?: string[]; store?: TokenStore; }
export class YeboID {
  private readonly config: AppAuth.AuthConfiguration;
  private readonly issuer: string;
  private readonly store: TokenStore;
  private queue: Promise<unknown> = Promise.resolve();
  private refreshInFlight?: Promise<Tokens>;
  private metadata?: Record<string, unknown>;

  constructor(options: Options) {
    this.issuer = https(options.issuer ?? 'https://api.yeboid.com').replace(/\/$/, '');
    const issuer = new URL(this.issuer), callback = new URL(options.redirectUrl);
    if (issuer.pathname !== '/' || issuer.search || !options.clientId || callback.hash || callback.username || callback.password || callback.search || callback.protocol === 'http:') throw new YeboIDError('invalid_configuration');
    const scopes = [...new Set(options.scopes ?? ['openid', 'profile', 'offline_access'])];
    if (!scopes.includes('openid') || scopes.some(s => !s || /\s/.test(s))) throw new YeboIDError('invalid_scope');
    this.config = { issuer: this.issuer, clientId: options.clientId, redirectUrl: options.redirectUrl, scopes,
      usePKCE: true, useNonce: true, connectionTimeoutSeconds: 10 };
    this.store = options.store ?? new KeychainTokenStore(`${this.issuer}|${options.clientId}`);
  }
  private mutate<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.queue.then(operation);
    // Each caller gets its own failure. Recover only the queue so the next explicit operation can run.
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }
  private async request(url: string, form?: Record<string, string>, accessToken?: string): Promise<Record<string, unknown>> {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(url, { method: form ? 'POST' : 'GET', redirect: 'error', signal: controller.signal,
        headers: { Accept: 'application/json', ...(form ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
        body: form ? new URLSearchParams(form).toString() : undefined });
      if (!response.ok) throw new YeboIDError(`http_${response.status}`, response.status);
      const data: unknown = await response.json();
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw new YeboIDError('invalid_response');
      return data as Record<string, unknown>;
    } finally { clearTimeout(timer); }
  }
  private async discovery(): Promise<Record<string, unknown>> {
    if (this.metadata) return this.metadata;
    const data = await this.request(`${this.issuer}/.well-known/openid-configuration`);
    if (data.issuer !== this.issuer || !Array.isArray(data.code_challenge_methods_supported) || !data.code_challenge_methods_supported.includes('S256')) throw new YeboIDError('invalid_discovery');
    for (const key of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'revocation_endpoint', 'introspection_endpoint']) https(data[key]);
    if (!Array.isArray(data.scopes_supported) || this.config.scopes.some(s => !(data.scopes_supported as unknown[]).includes(s))) throw new YeboIDError('invalid_scope');
    this.metadata = data;
    return data;
  }
  async checkRegistration(): Promise<void> {
    const data = await this.request(`${this.issuer}/oauth/clients/${encodeURIComponent(this.config.clientId)}/configuration`);
    if (data.client_id !== this.config.clientId || !Array.isArray(data.redirect_uris) || !data.redirect_uris.includes(this.config.redirectUrl)) throw new YeboIDError('invalid_registration');
    if (!Array.isArray(data.scopes) || this.config.scopes.some(s => !(data.scopes as unknown[]).includes(s))) throw new YeboIDError('invalid_scope');
  }
  signIn(): Promise<Tokens> {
    return this.mutate(async () => {
      await this.checkRegistration();
      await this.discovery();
      const result = await AppAuth.authorize(this.config);
      if (result.tokenType.toLowerCase() !== 'bearer') throw new YeboIDError('invalid_token_response');
      const tokens: Tokens = { accessToken: result.accessToken, refreshToken: result.refreshToken || undefined, expiresAt: result.accessTokenExpirationDate };
      validateTokens(tokens);
      await this.store.save(tokens);
      return tokens;
    });
  }
  tokens(): Promise<Tokens | null> { return this.store.load(); }
  refresh(): Promise<Tokens> {
    if (this.refreshInFlight) return this.refreshInFlight;
    this.refreshInFlight = this.mutate(async () => {
      const current = await this.store.load();
      if (!current?.refreshToken) throw new YeboIDError('login_required');
      await this.discovery();
      // Omit scopes so refresh cannot attempt to widen consent.
      const result = await AppAuth.refresh({ ...this.config, scopes: [] }, { refreshToken: current.refreshToken });
      if (!result.refreshToken || result.tokenType.toLowerCase() !== 'bearer') throw new YeboIDError('invalid_token_response');
      const tokens: Tokens = { accessToken: result.accessToken, refreshToken: result.refreshToken, expiresAt: result.accessTokenExpirationDate };
      validateTokens(tokens);
      await this.store.save(tokens);
      return tokens;
    }).finally(() => { this.refreshInFlight = undefined; });
    return this.refreshInFlight;
  }
  async userInfo(): Promise<UserInfo> {
    const tokens = await this.store.load();
    if (!tokens || Date.parse(tokens.expiresAt) <= Date.now()) throw new YeboIDError('login_required');
    const data = await this.request((await this.discovery()).userinfo_endpoint as string, undefined, tokens.accessToken);
    if (typeof data.sub !== 'string' || !data.sub) throw new YeboIDError('invalid_userinfo');
    return data as unknown as UserInfo;
  }
  /** Fresh actual grants, never the configured scope wishlist. Enforce authorization in the product API. */
  async permissions(): Promise<string[]> {
    const tokens = await this.store.load();
    if (!tokens) throw new YeboIDError('login_required');
    const data = await this.request((await this.discovery()).introspection_endpoint as string,
      { client_id: this.config.clientId, token: tokens.accessToken, token_type_hint: 'access_token' });
    if (data.active !== true || data.client_id !== this.config.clientId || data.token_type !== 'Bearer' || typeof data.scope !== 'string') throw new YeboIDError('invalid_token', 401);
    return data.scope.split(/\s+/).filter(Boolean);
  }
  /** Revokes the app refresh token. Does not clear the shared browser SSO cookie. */
  signOut(): Promise<void> {
    return this.mutate(async () => {
      const tokens = await this.store.load();
      if (tokens?.refreshToken) {
        await this.discovery();
        await AppAuth.revoke(this.config, { tokenToRevoke: tokens.refreshToken, sendClientId: true, includeBasicAuth: false });
      }
      await this.store.clear();
    });
  }
}
