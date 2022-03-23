import React from 'react';
import { PAGE_STATE } from 'ui/constants';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const History = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/history'>History</Link>,
      ]}
    />
    History
    <HuntApp page={PAGE_STATE.history} />
  </div>
);
History.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/history',
}

export default History;
