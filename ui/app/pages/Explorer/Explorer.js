import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import { Link } from 'ui/helpers/Link';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';

const Explorer = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/explorer'>Explorer</Link>,
      ]}
    />
    Explorer
  </div>
);
Explorer.metadata = {
  position: 1,
  category: LeftNavMap.HUNTING
}

export default Explorer;
