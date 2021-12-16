import React from 'react';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const Alerts = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Stamus ND',
        <Link app to='stamus-nd/alerts'>Alerts</Link>,
      ]}
    />
    Alerts
  </div>
);
Alerts.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus-nd/alerts',
}

export default Alerts;
