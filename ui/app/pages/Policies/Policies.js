import React from 'react';
import { Link } from 'ui/helpers/Link';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';

const Policies = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='stamus/hunting/policies'>Policies</Link>,
      ]}
    />
    Policies
  </div>
);
Policies.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus/hunting/policies',
}

export default Policies;
