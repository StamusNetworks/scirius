import React from 'react';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const Dashboards = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='stamus/hunting/dashboards'>Dashboards</Link>,
      ]}
    />
    Dashboards
  </div>
);
Dashboards.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus/hunting/dashboards'
}

export default Dashboards;
