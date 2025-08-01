## API Report File for "@backstage/plugin-catalog-node"

> Do not edit this file. It is a report generated by [API Extractor](https://api-extractor.com/).

```ts
import { AddLocationRequest } from '@backstage/catalog-client';
import { AddLocationResponse } from '@backstage/catalog-client';
import { AnalyzeLocationRequest } from '@backstage/plugin-catalog-common';
import { AnalyzeLocationResponse } from '@backstage/plugin-catalog-common';
import { CatalogApi } from '@backstage/catalog-client';
import { CatalogRequestOptions } from '@backstage/catalog-client';
import { CatalogService } from '@backstage/plugin-catalog-node';
import { CatalogServiceRequestOptions } from '@backstage/plugin-catalog-node';
import { CompoundEntityRef } from '@backstage/catalog-model';
import { Entity } from '@backstage/catalog-model';
import { GetEntitiesByRefsRequest } from '@backstage/catalog-client';
import { GetEntitiesByRefsResponse } from '@backstage/catalog-client';
import { GetEntitiesRequest } from '@backstage/catalog-client';
import { GetEntitiesResponse } from '@backstage/catalog-client';
import { GetEntityAncestorsRequest } from '@backstage/catalog-client';
import { GetEntityAncestorsResponse } from '@backstage/catalog-client';
import { GetEntityFacetsRequest } from '@backstage/catalog-client';
import { GetEntityFacetsResponse } from '@backstage/catalog-client';
import { GetLocationsResponse } from '@backstage/catalog-client';
import { Location as Location_2 } from '@backstage/catalog-client';
import { QueryEntitiesRequest } from '@backstage/catalog-client';
import { QueryEntitiesResponse } from '@backstage/catalog-client';
import { ServiceFactory } from '@backstage/backend-plugin-api';
import { ServiceMock } from '@backstage/backend-test-utils';
import { ValidateEntityResponse } from '@backstage/catalog-client';

// @public
export interface CatalogServiceMock extends CatalogService, CatalogApi {
  // (undocumented)
  addLocation(
    location: AddLocationRequest,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<AddLocationResponse>;
  // (undocumented)
  analyzeLocation(
    location: AnalyzeLocationRequest,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<AnalyzeLocationResponse>;
  // (undocumented)
  getEntities(
    request?: GetEntitiesRequest,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<GetEntitiesResponse>;
  // (undocumented)
  getEntitiesByRefs(
    request: GetEntitiesByRefsRequest,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<GetEntitiesByRefsResponse>;
  // (undocumented)
  getEntityAncestors(
    request: GetEntityAncestorsRequest,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<GetEntityAncestorsResponse>;
  // (undocumented)
  getEntityByRef(
    entityRef: string | CompoundEntityRef,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<Entity | undefined>;
  // (undocumented)
  getEntityFacets(
    request: GetEntityFacetsRequest,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<GetEntityFacetsResponse>;
  // (undocumented)
  getLocationByEntity(
    entityRef: string | CompoundEntityRef,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<Location_2 | undefined>;
  // (undocumented)
  getLocationById(
    id: string,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<Location_2 | undefined>;
  // (undocumented)
  getLocationByRef(
    locationRef: string,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<Location_2 | undefined>;
  // (undocumented)
  getLocations(
    request?: {},
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<GetLocationsResponse>;
  // (undocumented)
  queryEntities(
    request?: QueryEntitiesRequest,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<QueryEntitiesResponse>;
  // (undocumented)
  refreshEntity(
    entityRef: string,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<void>;
  // (undocumented)
  removeEntityByUid(
    uid: string,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<void>;
  // (undocumented)
  removeLocationById(
    id: string,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<void>;
  // (undocumented)
  validateEntity(
    entity: Entity,
    locationRef: string,
    options?: CatalogServiceRequestOptions | CatalogRequestOptions,
  ): Promise<ValidateEntityResponse>;
}

// @public
export function catalogServiceMock(options?: {
  entities?: Entity[];
}): CatalogServiceMock;

// @public
export namespace catalogServiceMock {
  const factory: (options?: {
    entities?: Entity[];
  }) => ServiceFactory<CatalogServiceMock, 'plugin', 'singleton'>;
  const mock: (
    partialImpl?: Partial<CatalogServiceMock> | undefined,
  ) => ServiceMock<CatalogServiceMock>;
}
```
