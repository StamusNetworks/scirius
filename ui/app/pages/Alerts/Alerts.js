import React from 'react';
import { PAGE_STATE } from 'ui/constants';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const Alerts = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/alerts'>Alerts</Link>,
      ]}
    />
    Alerts
    <HuntApp page={PAGE_STATE.alerts_list} />
  </div>
);
Alerts.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/alerts',
}

export default Alerts;
