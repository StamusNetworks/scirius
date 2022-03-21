import React from 'react';
import { PAGE_STATE } from 'constants';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const Alerts = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='stamus/hunting/alerts'>Alerts</Link>,
      ]}
    />
    Alerts
    <HuntApp page={PAGE_STATE.alerts_list} />
  </div>
);
Alerts.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus/hunting/alerts',
}

export default Alerts;
