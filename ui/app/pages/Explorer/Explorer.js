import React from 'react';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const Explorer = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Stamus ND',
        <Link app to="stamus-nd/explorer">
          Explorer
        </Link>,
      ]}
    />
    Explorer
  </div>
);
Explorer.metadata = {
  category: 'STAMUS_ND',
};

export default Explorer;
