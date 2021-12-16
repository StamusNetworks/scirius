import React from 'react';
import { Link } from 'ui/helpers/Link';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';

const Explorer = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Stamus ND',
        <Link app to='stamus-nd/explorer'>Explorer</Link>,
      ]}
    />
    Explorer
  </div>
);
Explorer.metadata = {
  category: 'STAMUS_ND'
}

export default Explorer;
