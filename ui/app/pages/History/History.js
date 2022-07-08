import React from 'react';
import { PAGE_STATE } from 'ui/constants';
import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const History = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Administration',
        <Link app to="administration/history">
          History
        </Link>,
      ]}
    />
    <HuntApp page={PAGE_STATE.history} />
  </div>
);
History.metadata = {
  category: 'ADMINISTRATION',
  url: 'administration/history',
};

export default History;
