/*
 * Copyright 2023 The Backstage Authors
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
  createSignInResolverFactory,
  SignInInfo,
  commonSignInResolvers,
  OAuthAuthenticatorResult,
  handleSignInUserNotFound,
} from '@backstage/plugin-auth-node';
import { OidcAuthResult } from './authenticator';
import { z } from 'zod';

/**
 * Available sign-in resolvers for the Oidc auth provider.
 *
 * @public
 */
export namespace oidcSignInResolvers {
  /**
   * A oidc resolver that looks up the user using the local part of
   * their email address as the entity name.
   */
  export const emailLocalPartMatchingUserEntityName =
    commonSignInResolvers.emailLocalPartMatchingUserEntityName;

  /**
   * A oidc resolver that looks up the user using their email address
   * as email of the entity.
   */
  export const emailMatchingUserEntityProfileEmail =
    commonSignInResolvers.emailMatchingUserEntityProfileEmail;

  /**
   * A oidc resolver that looks up the user using their preferred username
   * as the entity name
   */
  export const preferredUsernameMatchingUserEntityName =
    createSignInResolverFactory({
      optionsSchema: z
        .object({
          dangerouslyAllowSignInWithoutUserInCatalog: z.boolean().optional(),
        })
        .optional(),
      create(options) {
        return async (
          info: SignInInfo<OAuthAuthenticatorResult<OidcAuthResult>>,
          ctx,
        ) => {
          const userId = info.result.fullProfile.userinfo.preferred_username;
          if (!userId) {
            throw new Error(`OIDC user profile does not contain a username`);
          }
          try {
            return await ctx.signInWithCatalogUser({
              entityRef: { name: userId },
            });
          } catch (error) {
            return await handleSignInUserNotFound({
              ctx,
              error,
              userEntityName: userId,
              dangerouslyAllowSignInWithoutUserInCatalog:
                options?.dangerouslyAllowSignInWithoutUserInCatalog,
            });
          }
        };
      },
    });
}
