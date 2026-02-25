/*
 * Copyright 2020 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  PassportOAuthAuthenticatorHelper,
  PassportProfile,
} from '@backstage/plugin-auth-node';
import { githubAuthenticator } from './authenticator';

describe('githubAuthenticator', () => {
  it('should store access token without expiration as refresh token', async () => {
    await expect(
      githubAuthenticator.authenticate(
        {} as any,
        {
          authenticate: async _input => ({
            fullProfile: { id: 'id' } as PassportProfile,
            session: {
              accessToken: 'my-token',
              scope: 'user:read',
              tokenType: 'bearer',
            },
          }),
        } as PassportOAuthAuthenticatorHelper,
      ),
    ).resolves.toEqual({
      fullProfile: { id: 'id' },
      session: {
        accessToken: 'my-token',
        scope: 'user:read',
        tokenType: 'bearer',
        refreshToken: 'access-token-v2.my-token',
      },
    });
  });

  it('should not use access token as refresh token if it expires', async () => {
    await expect(
      githubAuthenticator.authenticate(
        {} as any,
        {
          authenticate: async _input => ({
            fullProfile: { id: 'id' } as PassportProfile,
            session: {
              accessToken: 'my-token',
              scope: 'user:read',
              tokenType: 'bearer',
              expiresInSeconds: 3,
            },
          }),
        } as PassportOAuthAuthenticatorHelper,
      ),
    ).resolves.toEqual({
      fullProfile: { id: 'id' },
      session: {
        accessToken: 'my-token',
        scope: 'user:read',
        tokenType: 'bearer',
        expiresInSeconds: 3,
      },
    });
  });

  it('should not store access token without expiration if a refresh token is provided', async () => {
    await expect(
      githubAuthenticator.authenticate(
        {} as any,
        {
          authenticate: async _input => ({
            fullProfile: { id: 'id' } as PassportProfile,
            session: {
              accessToken: 'my-token',
              scope: 'user:read',
              tokenType: 'bearer',
              refreshToken: 'my-refresh-token',
            },
          }),
        } as PassportOAuthAuthenticatorHelper,
      ),
    ).resolves.toEqual({
      fullProfile: { id: 'id' },
      session: {
        accessToken: 'my-token',
        scope: 'user:read',
        tokenType: 'bearer',
        refreshToken: 'my-refresh-token',
      },
    });
  });

  it('should refresh with access token', async () => {
    await expect(
      githubAuthenticator.refresh(
        {
          refreshToken: 'access-token-v2.my-token',
          req: {} as any,
          scope: 'user:read',
          scopeAlreadyGranted: true,
        },
        {
          fetchProfile: async _input => ({ id: 'id' } as PassportProfile),
        } as PassportOAuthAuthenticatorHelper,
      ),
    ).resolves.toEqual({
      fullProfile: { id: 'id' },
      session: {
        accessToken: 'my-token',
        scope: 'user:read',
        tokenType: 'bearer',
        refreshToken: 'access-token-v2.my-token',
      },
    });
  });

  it('should fail refresh if scope has not already been granted', async () => {
    await expect(
      githubAuthenticator.refresh(
        {
          refreshToken: 'access-token-v2.my-token',
          req: {} as any,
          scope: 'user:read',
        },
        {
          fetchProfile: async _input => ({ id: 'id' } as PassportProfile),
        } as PassportOAuthAuthenticatorHelper,
      ),
    ).rejects.toThrow(
      'Refresh failed, session has not been granted the requested scope',
    );
  });

  it('should refresh with refresh token', async () => {
    const res = {};
    await expect(
      githubAuthenticator.refresh(
        {
          refreshToken: 'my-refresh-token',
          req: {} as any,
          scope: 'user:read',
        },
        {
          refresh: async _input => res as any,
        } as PassportOAuthAuthenticatorHelper,
      ),
    ).resolves.toBe(res);
  });

  it('should handle GitHub SAML SSO session expiration (403 with x-github-sso header)', async () => {
    // Simulate the error that GitHub returns when SAML SSO session expires
    const samlSsoError = new Error('Request failed with status code 403');
    (samlSsoError as any).oauthError = {
      statusCode: 403,
      data: {
        message:
          'Resource protected by organization SAML enforcement. You must grant your Personal Access token access to this organization.',
        documentation_url:
          'https://docs.github.com/articles/authenticating-to-a-github-organization-with-saml-single-sign-on/',
      },
    };
    (samlSsoError as any).response = {
      headers: {
        'x-github-sso':
          'required; url=https://github.com/orgs/test-org/sso?authorization_request=ABC123',
      },
    };

    await expect(
      githubAuthenticator.refresh(
        {
          refreshToken: 'access-token-v2.my-token',
          req: {} as any,
          scope: 'user:read',
          scopeAlreadyGranted: true,
        },
        {
          fetchProfile: async () => {
            throw samlSsoError;
          },
        } as unknown as PassportOAuthAuthenticatorHelper,
      ),
    ).rejects.toMatchObject({
      name: 'GitHubSamlSsoExpiredError',
      message: expect.stringContaining('SAML SSO session has expired'),
      ssoUrl:
        'https://github.com/orgs/test-org/sso?authorization_request=ABC123',
      statusCode: 403,
    });
  });

  it('should handle 401 unauthorized error during refresh', async () => {
    const unauthorizedError = new Error('Invalid access token');
    (unauthorizedError as any).oauthError = {
      statusCode: 401,
    };

    await expect(
      githubAuthenticator.refresh(
        {
          refreshToken: 'access-token-v2.my-token',
          req: {} as any,
          scope: 'user:read',
          scopeAlreadyGranted: true,
        },
        {
          fetchProfile: async () => {
            throw unauthorizedError;
          },
        } as unknown as PassportOAuthAuthenticatorHelper,
      ),
    ).rejects.toThrow('Invalid access token');
  });

  it('should handle regular 403 errors without x-github-sso header', async () => {
    const regularForbiddenError = new Error('Access forbidden');
    (regularForbiddenError as any).oauthError = {
      statusCode: 403,
      data: {
        message: 'Resource not accessible',
      },
    };
    (regularForbiddenError as any).response = {
      headers: {},
    };

    await expect(
      githubAuthenticator.refresh(
        {
          refreshToken: 'access-token-v2.my-token',
          req: {} as any,
          scope: 'user:read',
          scopeAlreadyGranted: true,
        },
        {
          fetchProfile: async () => {
            throw regularForbiddenError;
          },
        } as unknown as PassportOAuthAuthenticatorHelper,
      ),
    ).rejects.toThrow('Access forbidden');
  });
});
