import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import { Link } from 'ui/helpers/Link';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';

const Policies = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/policies'>Policies</Link>,
      ]}
    />
    Policies
  </div>
);
Policies.metadata = {
  position: 4,
  category: LeftNavMap.HUNTING,
  url: 'hunting/policies',
}

export default Policies;
