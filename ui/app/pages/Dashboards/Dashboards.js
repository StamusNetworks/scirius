import React from 'react';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

import DashboardPage from './DashboardPage';

const Dashboards = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to="hunting/dashboards">
          Dashboards
        </Link>,
      ]}
    />
    <DashboardPage />
  </div>
);
Dashboards.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/dashboards',
  position: 0,
};

export default Dashboards;
