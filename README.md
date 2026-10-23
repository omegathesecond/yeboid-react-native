# YeboID for React Native

Native AppAuth sign-in for iOS/Android, with PKCE/state/nonce handling, Keychain/Keystore storage and serialized session changes. Expo requires a **development build**; Expo Go does not contain these native modules. Read [AGENTS.md](AGENTS.md).

## Install the source-release artifact

```sh
npm install https://github.com/omegathesecond/yeboid-react-native/releases/download/v0.1.0/yeboid-react-native-0.1.0.tgz react-native-app-auth react-native-keychain
cd ios && pod install
```

The tarball includes built JS and TypeScript declarations. This is a GitHub release artifact; no npm registry publication is claimed. Match the native dependency versions to your host's React Native version using the [AppAuth setup guide](https://github.com/FormidableLabs/react-native-app-auth). This wrapper adds no custom native bridge.

Register `com.yourcompany.yourapp://oauth/callback` exactly in [Developer Apps](https://yeboid.com/developer/apps). Configure the iOS URL scheme + AppAuth application delegate/scene callback, Android `appAuthRedirectScheme`, and secure-storage native capabilities following the native dependencies' installation guides. Rebuild the native host after linking. PKCE does not replace native URL routing.

## Use one client instance

```typescript
import { YeboID } from 'yeboid-react-native';

export const identity = new YeboID({
  clientId: 'YOUR_PUBLIC_CLIENT_ID',
  redirectUrl: 'com.yourcompany.yourapp://oauth/callback',
});

async function signIn() {
  try {
    await identity.signIn();
    const user = await identity.userInfo();
    // Persist only user.sub as yeboid_user_id in the product database.
    return user;
  } catch (error) {
    // Route this to your app's normal error UI, then propagate as appropriate.
    throw error;
  }
}

const tokens = await identity.tokens(); // secure restore, or null when signed out
const granted = await identity.permissions(); // fresh actual grants, from introspection
await identity.refresh();               // single-flight and durable rotation
await identity.signOut();               // revoke before secure deletion
```

Defaults request `openid profile offline_access`. Extra scopes require explicit registration and fresh consent. `permissions()` asks for current granted scopes; do not use the configured scope list to grant capabilities. Your API must verify the access token, required scopes and resource ownership. Never use an ID token as an API bearer credential.

Discovery supplies the hosted login and API endpoints. No client secret belongs in the app. Default `KeychainTokenStore` isolates sessions by issuer/client. Custom stores must encrypt and propagate failures; AsyncStorage is not suitable for tokens. Disable/exclude Android credential backups according to the host application's backup policy.

Native cancellation, discovery errors, refresh/revoke failures and persistence errors reject their promises. Show them through the existing app UI. Sign-out waits for an in-flight rotation and revokes its newly saved token; failures preserve local state. Sign-out does not clear system-browser SSO cookies. If a refresh's network/storage result is uncertain, require fresh sign-in instead of retrying the old refresh token.

```sh
npm ci --legacy-peer-deps
npm run typecheck
npm test
npm run build
npm pack
```

Tests mock native modules and network responses. A passing build is not proof of native linking or device login. Test callbacks, cancellation, returning-user login, refresh and logout on an actual configured host app.
