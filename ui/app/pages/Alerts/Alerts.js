import React from 'react';
import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import AlertsPage from './AlertsPage';

const Alerts = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to="hunting/alerts">
          Alerts
        </Link>,
      ]}
    />
    <AlertsPage />
  </div>
);
Alerts.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/alerts',
  position: 1,
};

export default Alerts;
