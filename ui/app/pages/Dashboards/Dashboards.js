import React from 'react';
import { PAGE_STATE } from 'constants';
import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const Dashboards = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/dashboards'>Dashboards</Link>,
      ]}
    />
    <HuntApp page={PAGE_STATE.dashboards} />
  </div>
);
Dashboards.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/dashboards',
  position: 0,
}

export default Dashboards;
