## API Report File for "@backstage/plugin-kubernetes"

> Do not edit this file. It is a report generated by [API Extractor](https://api-extractor.com/).

```ts
/// <reference types="react" />

import { BackstagePlugin } from '@backstage/core-plugin-api';
import { Entity } from '@backstage/catalog-model';
import { default as React_2 } from 'react';
import { RouteRef } from '@backstage/core-plugin-api';

// Warning: (ae-missing-release-tag) "EntityKubernetesContent" is part of the package's API, but it is missing a release tag (@alpha, @beta, @public, or @internal)
//
// @public (undocumented)
export const EntityKubernetesContent: (
  props: EntityKubernetesContentProps,
) => JSX.Element;

// @public
export type EntityKubernetesContentProps = {
  refreshIntervalMs?: number;
};

// Warning: (ae-missing-release-tag) "isKubernetesAvailable" is part of the package's API, but it is missing a release tag (@alpha, @beta, @public, or @internal)
//
// @public (undocumented)
export const isKubernetesAvailable: (entity: Entity) => boolean;

// Warning: (ae-missing-release-tag) "kubernetesPlugin" is part of the package's API, but it is missing a release tag (@alpha, @beta, @public, or @internal)
//
// @public (undocumented)
const kubernetesPlugin: BackstagePlugin<
  {
    entityContent: RouteRef<undefined>;
  },
  {}
>;
export { kubernetesPlugin };
export { kubernetesPlugin as plugin };

// Warning: (ae-missing-release-tag) "Router" is part of the package's API, but it is missing a release tag (@alpha, @beta, @public, or @internal)
//
// @public (undocumented)
export const Router: (props: {
  refreshIntervalMs?: number;
}) => React_2.JSX.Element;

export * from '@backstage/plugin-kubernetes-react';

// Warnings were encountered during analysis:
//
// src/Router.d.ts:3:22 - (ae-undocumented) Missing documentation for "isKubernetesAvailable".
// src/Router.d.ts:4:22 - (ae-undocumented) Missing documentation for "Router".
// src/plugin.d.ts:3:22 - (ae-undocumented) Missing documentation for "kubernetesPlugin".
// src/plugin.d.ts:17:22 - (ae-undocumented) Missing documentation for "EntityKubernetesContent".
```