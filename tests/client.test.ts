import { beforeEach, expect, it, vi } from 'vitest';
vi.mock('react-native-app-auth', () => ({ authorize: vi.fn(), refresh: vi.fn(), revoke: vi.fn() }));
vi.mock('react-native-keychain', () => ({}));
import * as native from 'react-native-app-auth';
import { YeboID, type Tokens, type TokenStore } from '../src/index';
const response = { accessToken: 'access', refreshToken: 'refresh', accessTokenExpirationDate: '2099-01-01T00:00:00Z', tokenType: 'Bearer' };
let value: Tokens | null;
let client: YeboID;
let store: TokenStore;
beforeEach(() => {
  vi.resetAllMocks(); value = null;
  store = { load: async () => value, save: async t => { value = t; }, clear: async () => { value = null; } };
  client = new YeboID({clientId:'app',redirectUrl:'com.example://callback',store});
  vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(JSON.stringify(url.endsWith('/configuration') ?
    { client_id:'app',redirect_uris:['com.example://callback'],scopes:['openid','profile','offline_access'] } : {issuer:'https://api.yeboid.com',scopes_supported:['openid','profile','offline_access'],
    code_challenge_methods_supported:['S256'], authorization_endpoint:'https://yeboid.com/oauth/authorize',token_endpoint:'https://api.yeboid.com/oauth/token',
    userinfo_endpoint:'https://api.yeboid.com/oauth/userinfo',revocation_endpoint:'https://api.yeboid.com/oauth/revoke',introspection_endpoint:'https://api.yeboid.com/oauth/introspect'}))));
  vi.mocked(native.authorize).mockResolvedValue(response as native.AuthorizeResult);
  vi.mocked(native.refresh).mockResolvedValue({...response,refreshToken:'rotated'} as native.RefreshResult);
});
it('delegates PKCE/state/nonce to native AppAuth and stores tokens', async () => {
  await client.signIn();
  expect(native.authorize).toHaveBeenCalledWith(expect.objectContaining({issuer:'https://api.yeboid.com',usePKCE:true,useNonce:true}));
  expect(value?.accessToken).toBe('access');
});
it('shares concurrent refreshes and persists rotation without scope expansion', async () => {
  await client.signIn();
  await Promise.all([client.refresh(),client.refresh(),client.refresh()]);
  expect(native.refresh).toHaveBeenCalledTimes(1);
  expect(native.refresh).toHaveBeenCalledWith(expect.objectContaining({scopes:[]}),{refreshToken:'refresh'});
  expect(value?.refreshToken).toBe('rotated');
});
it('logout waits for refresh then revokes the newly rotated token', async () => {
  await client.signIn();
  await Promise.all([client.refresh(),client.signOut()]);
  expect(native.revoke).toHaveBeenCalledWith(expect.anything(),{tokenToRevoke:'rotated',sendClientId:true,includeBasicAuth:false});
  expect(value).toBeNull();
});
it('surfaces network failures without opening the native browser', async () => {
  vi.mocked(fetch).mockRejectedValue(new Error('offline'));
  await expect(client.signIn()).rejects.toThrow('offline');
  expect(native.authorize).not.toHaveBeenCalled();
});
it('surfaces cancellation, refresh, logout and storage errors', async () => {
  vi.mocked(native.authorize).mockRejectedValueOnce(new Error('cancelled'));
  await expect(client.signIn()).rejects.toThrow('cancelled');
  await client.signIn();
  vi.mocked(native.refresh).mockRejectedValueOnce(new Error('invalid_grant'));
  await expect(client.refresh()).rejects.toThrow('invalid_grant');
  vi.mocked(native.revoke).mockRejectedValueOnce(new Error('offline'));
  await expect(client.signOut()).rejects.toThrow('offline');
  expect(value).not.toBeNull();
  store.save = async () => { throw new Error('storage'); };
  await expect(client.refresh()).rejects.toThrow('storage');
});
it('does not fabricate a user or grants from malformed API replies', async () => {
  await client.signIn();
  vi.mocked(fetch).mockResolvedValue(new Response('{}'));
  await expect(client.userInfo()).rejects.toThrow('invalid_userinfo');
  vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({active:false})));
  await expect(client.permissions()).rejects.toThrow('invalid_token');
});
it('rejects callback and scope registration mismatches before native authorization', async () => {
  vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({client_id:'app',redirect_uris:['other://callback'],scopes:['openid','profile','offline_access']})));
  await expect(client.signIn()).rejects.toThrow('invalid_registration');
  vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({client_id:'app',redirect_uris:['com.example://callback'],scopes:['openid']})));
  await expect(client.signIn()).rejects.toThrow('invalid_scope');
  expect(native.authorize).not.toHaveBeenCalled();
});
