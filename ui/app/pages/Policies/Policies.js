import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
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
  position: 4,
  category: LeftNavMap.STAMUS_ND,
  url: 'stamus-nd/policies',
}

export default Policies;
