import React from 'react';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const Alerts = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='stamus/hunting/alerts'>Alerts</Link>,
      ]}
    />
    Alerts
  </div>
);
Alerts.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus/hunting/alerts',
}

export default Alerts;
