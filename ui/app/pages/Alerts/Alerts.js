import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const Alerts = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/alerts'>Alerts</Link>,
      ]}
    />
    Alerts
  </div>
);
Alerts.metadata = {
  position: 0,
  category: LeftNavMap.HUNTING,
  url: 'hunting/alerts',
}

export default Alerts;
