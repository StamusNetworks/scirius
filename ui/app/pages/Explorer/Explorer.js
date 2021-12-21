import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
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
  position: 1,
  category: LeftNavMap.STAMUS_ND
}

export default Explorer;
