## API Report File for "@backstage/plugin-techdocs"

> Do not edit this file. It is a report generated by [API Extractor](https://api-extractor.com/).

```ts
import { AnyApiFactory } from '@backstage/frontend-plugin-api';
import { AnyExtensionDataRef } from '@backstage/frontend-plugin-api';
import { AnyRouteRefParams } from '@backstage/frontend-plugin-api';
import { ApiFactory } from '@backstage/frontend-plugin-api';
import { ConfigurableExtensionDataRef } from '@backstage/frontend-plugin-api';
import { defaultEntityContentGroups } from '@backstage/plugin-catalog-react/alpha';
import { Entity } from '@backstage/catalog-model';
import { EntityPredicate } from '@backstage/plugin-catalog-react/alpha';
import { ExtensionBlueprintParams } from '@backstage/frontend-plugin-api';
import { ExtensionDefinition } from '@backstage/frontend-plugin-api';
import { ExtensionInput } from '@backstage/frontend-plugin-api';
import { FrontendPlugin } from '@backstage/frontend-plugin-api';
import { IconComponent } from '@backstage/core-plugin-api';
import { IconLinkVerticalProps } from '@backstage/core-components';
import { JSX as JSX_2 } from 'react';
import { RouteRef } from '@backstage/frontend-plugin-api';
import { SearchResultItemExtensionComponent } from '@backstage/plugin-search-react/alpha';
import { SearchResultItemExtensionPredicate } from '@backstage/plugin-search-react/alpha';
import { SearchResultListItemBlueprintParams } from '@backstage/plugin-search-react/alpha';
import { TechDocsAddonOptions } from '@backstage/plugin-techdocs-react';

// @alpha (undocumented)
const _default: FrontendPlugin<
  {
    root: RouteRef<undefined>;
    docRoot: RouteRef<{
      name: string;
      kind: string;
      namespace: string;
    }>;
    entityContent: RouteRef<undefined>;
  },
  {},
  {
    'api:techdocs': ExtensionDefinition<{
      kind: 'api';
      name: undefined;
      config: {};
      configInput: {};
      output: ConfigurableExtensionDataRef<
        AnyApiFactory,
        'core.api.factory',
        {}
      >;
      inputs: {};
      params: <
        TApi,
        TImpl extends TApi,
        TDeps extends { [name in string]: unknown },
      >(
        params: ApiFactory<TApi, TImpl, TDeps>,
      ) => ExtensionBlueprintParams<AnyApiFactory>;
    }>;
    'api:techdocs/storage': ExtensionDefinition<{
      kind: 'api';
      name: 'storage';
      config: {};
      configInput: {};
      output: ConfigurableExtensionDataRef<
        AnyApiFactory,
        'core.api.factory',
        {}
      >;
      inputs: {};
      params: <
        TApi,
        TImpl extends TApi,
        TDeps extends { [name in string]: unknown },
      >(
        params: ApiFactory<TApi, TImpl, TDeps>,
      ) => ExtensionBlueprintParams<AnyApiFactory>;
    }>;
    'empty-state:techdocs/entity-content': ExtensionDefinition<{
      config: {};
      configInput: {};
      output: ConfigurableExtensionDataRef<
        JSX_2.Element,
        'core.reactElement',
        {
          optional: true;
        }
      >;
      inputs: {
        [x: string]: ExtensionInput<
          AnyExtensionDataRef,
          {
            optional: boolean;
            singleton: boolean;
          }
        >;
      };
      params: never;
      kind: 'empty-state';
      name: 'entity-content';
    }>;
    'entity-content:techdocs': ExtensionDefinition<{
      config: {
        path: string | undefined;
        title: string | undefined;
        filter: EntityPredicate | undefined;
        group: string | false | undefined;
      };
      configInput: {
        filter?: EntityPredicate | undefined;
        title?: string | undefined;
        path?: string | undefined;
        group?: string | false | undefined;
      };
      output:
        | ConfigurableExtensionDataRef<JSX_2.Element, 'core.reactElement', {}>
        | ConfigurableExtensionDataRef<string, 'core.routing.path', {}>
        | ConfigurableExtensionDataRef<
            RouteRef<AnyRouteRefParams>,
            'core.routing.ref',
            {
              optional: true;
            }
          >
        | ConfigurableExtensionDataRef<
            string,
            'catalog.entity-content-title',
            {}
          >
        | ConfigurableExtensionDataRef<
            (entity: Entity) => boolean,
            'catalog.entity-filter-function',
            {
              optional: true;
            }
          >
        | ConfigurableExtensionDataRef<
            string,
            'catalog.entity-filter-expression',
            {
              optional: true;
            }
          >
        | ConfigurableExtensionDataRef<
            string,
            'catalog.entity-content-group',
            {
              optional: true;
            }
          >;
      inputs: {
        addons: ExtensionInput<
          ConfigurableExtensionDataRef<
            TechDocsAddonOptions,
            'techdocs.addon',
            {}
          >,
          {
            singleton: false;
            optional: false;
          }
        >;
        emptyState: ExtensionInput<
          ConfigurableExtensionDataRef<
            JSX_2.Element,
            'core.reactElement',
            {
              optional: true;
            }
          >,
          {
            singleton: true;
            optional: true;
          }
        >;
      };
      kind: 'entity-content';
      name: undefined;
      params: {
        loader: () => Promise<JSX.Element>;
        defaultPath: string;
        defaultTitle: string;
        defaultGroup?: keyof defaultEntityContentGroups | (string & {});
        routeRef?: RouteRef;
        filter?: string | EntityPredicate | ((entity: Entity) => boolean);
      };
    }>;
    'entity-icon-link:techdocs/read-docs': ExtensionDefinition<{
      kind: 'entity-icon-link';
      name: 'read-docs';
      config: {
        label: string | undefined;
        title: string | undefined;
        filter: EntityPredicate | undefined;
      };
      configInput: {
        filter?: EntityPredicate | undefined;
        label?: string | undefined;
        title?: string | undefined;
      };
      output:
        | ConfigurableExtensionDataRef<
            (entity: Entity) => boolean,
            'catalog.entity-filter-function',
            {
              optional: true;
            }
          >
        | ConfigurableExtensionDataRef<
            string,
            'catalog.entity-filter-expression',
            {
              optional: true;
            }
          >
        | ConfigurableExtensionDataRef<
            () => IconLinkVerticalProps,
            'entity-icon-link-props',
            {}
          >;
      inputs: {};
      params: {
        useProps: () => Omit<IconLinkVerticalProps, 'color'>;
        filter?: EntityPredicate | ((entity: Entity) => boolean);
      };
    }>;
    'nav-item:techdocs': ExtensionDefinition<{
      kind: 'nav-item';
      name: undefined;
      config: {};
      configInput: {};
      output: ConfigurableExtensionDataRef<
        {
          title: string;
          icon: IconComponent;
          routeRef: RouteRef<undefined>;
        },
        'core.nav-item.target',
        {}
      >;
      inputs: {};
      params: {
        title: string;
        icon: IconComponent;
        routeRef: RouteRef<undefined>;
      };
    }>;
    'page:techdocs': ExtensionDefinition<{
      kind: 'page';
      name: undefined;
      config: {
        path: string | undefined;
      };
      configInput: {
        path?: string | undefined;
      };
      output:
        | ConfigurableExtensionDataRef<JSX_2.Element, 'core.reactElement', {}>
        | ConfigurableExtensionDataRef<string, 'core.routing.path', {}>
        | ConfigurableExtensionDataRef<
            RouteRef<AnyRouteRefParams>,
            'core.routing.ref',
            {
              optional: true;
            }
          >;
      inputs: {};
      params: {
        defaultPath: string;
        loader: () => Promise<JSX.Element>;
        routeRef?: RouteRef;
      };
    }>;
    'page:techdocs/reader': ExtensionDefinition<{
      config: {
        path: string | undefined;
      };
      configInput: {
        path?: string | undefined;
      };
      output:
        | ConfigurableExtensionDataRef<JSX_2.Element, 'core.reactElement', {}>
        | ConfigurableExtensionDataRef<string, 'core.routing.path', {}>
        | ConfigurableExtensionDataRef<
            RouteRef<AnyRouteRefParams>,
            'core.routing.ref',
            {
              optional: true;
            }
          >;
      inputs: {
        addons: ExtensionInput<
          ConfigurableExtensionDataRef<
            TechDocsAddonOptions,
            'techdocs.addon',
            {}
          >,
          {
            singleton: false;
            optional: false;
          }
        >;
      };
      kind: 'page';
      name: 'reader';
      params: {
        defaultPath: string;
        loader: () => Promise<JSX.Element>;
        routeRef?: RouteRef;
      };
    }>;
    'search-result-list-item:techdocs': ExtensionDefinition<{
      config: {
        title: string | undefined;
        lineClamp: number;
        asLink: boolean;
        asListItem: boolean;
      } & {
        noTrack: boolean;
      };
      configInput: {
        title?: string | undefined;
        lineClamp?: number | undefined;
        asListItem?: boolean | undefined;
        asLink?: boolean | undefined;
      } & {
        noTrack?: boolean | undefined;
      };
      output: ConfigurableExtensionDataRef<
        {
          predicate?: SearchResultItemExtensionPredicate;
          component: SearchResultItemExtensionComponent;
        },
        'search.search-result-list-item.item',
        {}
      >;
      inputs: {
        [x: string]: ExtensionInput<
          AnyExtensionDataRef,
          {
            optional: boolean;
            singleton: boolean;
          }
        >;
      };
      kind: 'search-result-list-item';
      name: undefined;
      params: SearchResultListItemBlueprintParams;
    }>;
  }
>;
export default _default;

// @alpha (undocumented)
export const techDocsSearchResultListItemExtension: ExtensionDefinition<{
  config: {
    title: string | undefined;
    lineClamp: number;
    asLink: boolean;
    asListItem: boolean;
  } & {
    noTrack: boolean;
  };
  configInput: {
    title?: string | undefined;
    lineClamp?: number | undefined;
    asListItem?: boolean | undefined;
    asLink?: boolean | undefined;
  } & {
    noTrack?: boolean | undefined;
  };
  output: ConfigurableExtensionDataRef<
    {
      predicate?: SearchResultItemExtensionPredicate;
      component: SearchResultItemExtensionComponent;
    },
    'search.search-result-list-item.item',
    {}
  >;
  inputs: {
    [x: string]: ExtensionInput<
      AnyExtensionDataRef,
      {
        optional: boolean;
        singleton: boolean;
      }
    >;
  };
  kind: 'search-result-list-item';
  name: undefined;
  params: SearchResultListItemBlueprintParams;
}>;

// (No @packageDocumentation comment for this package)
```
