import React from 'react';
import pages from 'ui/pages';
import { Route, Switch } from 'react-router-dom';

const ProxyRoute = () => <Switch><Route component={pages.NotFoundPage} /></Switch>;

export default ProxyRoute;
