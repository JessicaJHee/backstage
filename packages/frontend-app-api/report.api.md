## API Report File for "@backstage/frontend-app-api"

> Do not edit this file. It is a report generated by [API Extractor](https://api-extractor.com/).

```ts
import { ApiHolder } from '@backstage/core-plugin-api';
import { AppTree } from '@backstage/frontend-plugin-api';
import { ConfigApi } from '@backstage/core-plugin-api';
import { ExtensionFactoryMiddleware } from '@backstage/frontend-plugin-api';
import { ExternalRouteRef } from '@backstage/frontend-plugin-api';
import { FrontendFeature as FrontendFeature_2 } from '@backstage/frontend-plugin-api';
import { FrontendPluginInfo } from '@backstage/frontend-plugin-api';
import { JsonObject } from '@backstage/types';
import { RouteRef } from '@backstage/frontend-plugin-api';
import { SubRouteRef } from '@backstage/frontend-plugin-api';

// @public
export type CreateAppRouteBinder = <
  TExternalRoutes extends {
    [name: string]: ExternalRouteRef;
  },
>(
  externalRoutes: TExternalRoutes,
  targetRoutes: PartialKeys<
    TargetRouteMap<TExternalRoutes>,
    KeysWithType<TExternalRoutes, ExternalRouteRef<any>>
  >,
) => void;

// @public
export function createSpecializedApp(options?: {
  features?: FrontendFeature_2[];
  config?: ConfigApi;
  bindRoutes?(context: { bind: CreateAppRouteBinder }): void;
  apis?: ApiHolder;
  extensionFactoryMiddleware?:
    | ExtensionFactoryMiddleware
    | ExtensionFactoryMiddleware[];
  flags?: {
    allowUnknownExtensionConfig?: boolean;
  };
  pluginInfoResolver?: FrontendPluginInfoResolver;
}): {
  apis: ApiHolder;
  tree: AppTree;
};

// @public @deprecated (undocumented)
export type FrontendFeature = FrontendFeature_2;

// @public
export type FrontendPluginInfoResolver = (ctx: {
  packageJson(): Promise<JsonObject | undefined>;
  manifest(): Promise<JsonObject | undefined>;
  defaultResolver(sources: {
    packageJson: JsonObject | undefined;
    manifest: JsonObject | undefined;
  }): Promise<{
    info: FrontendPluginInfo;
  }>;
}) => Promise<{
  info: FrontendPluginInfo;
}>;
```
