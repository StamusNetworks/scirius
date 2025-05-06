import React, { useEffect } from 'react';

import { useLocation } from 'react-router-dom/cjs/react-router-dom';
import { Redirect } from 'react-router-dom/cjs/react-router-dom.min';

import { APP_URL } from 'ui/config';
import { FiltersList } from 'ui/maps/Filters';
import { useStore } from 'ui/mobx/RootStoreProvider';
import Dashboards from 'ui/pages/Dashboards/Dashboards';
import Events from 'ui/pages/Events/Events';
import Signatures from 'ui/pages/Signatures/Signatures';
import Filter from 'ui/utils/Filter';

export default () => {
  const { commonStore } = useStore();
  const location = useLocation();
  const params = new URLSearchParams(location.search);

  useEffect(() => {
    commonStore.clearFilters();
    Array.from(params)?.forEach(([key, value]) => {
      if (key === 'page') return;
      if (!FiltersList.find(f => f.id === key)) return;

      if (value.startsWith('"') && value.endsWith('"')) {
        commonStore.addFilter(new Filter(key, value.slice(1, -1)));
      } else {
        commonStore.addFilter(new Filter(key, value));
      }
    });
  }, []);

  return <Redirect to={`${APP_URL}/${urls[params.get('page')] ?? urls.dashboard}/`} />;
};

const urls = {
  dashboard: Dashboards.metadata.url,
  events: Events.metadata.url,
  detection_methods: Signatures.metadata.url,
  hosts: 'hunting/hosts',
  inventory: 'analytics/inventory',
};
