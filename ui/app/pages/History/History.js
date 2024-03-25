import React from 'react';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

import HistoryPage from './HistoryPage';

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
    <HistoryPage />
  </div>
);
History.metadata = {
  category: 'ADMINISTRATION',
  url: 'administration/history',
};

export default History;
