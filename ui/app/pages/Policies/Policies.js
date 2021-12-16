import React from 'react';
import { Link } from 'ui/helpers/Link';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';

const Policies = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Stamus ND',
        <Link app to='stamus-nd/policies'>Policies</Link>,
      ]}
    />
    Policies
  </div>
);
Policies.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus-nd/policies',
}

export default Policies;
