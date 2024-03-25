import React from 'react';

import { Route, Switch } from 'react-router-dom';

import pages from 'ui/pages';

const ProxyRoute = () => (
  <Switch>
    <Route component={pages.NotFoundPage} />
  </Switch>
);

export default ProxyRoute;
