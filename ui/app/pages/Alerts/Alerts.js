import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
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
  position: 0,
  category: LeftNavMap.STAMUS_ND,
  url: 'stamus-nd/alerts',
}

export default Alerts;
