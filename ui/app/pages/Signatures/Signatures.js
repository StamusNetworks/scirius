import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const Signatures = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/signatures'>Signatures</Link>,
      ]}
    />
    Signatures
  </div>
);
Signatures.metadata = {
  position: 3,
  category: LeftNavMap.HUNTING,
  url: 'hunting/signatures',
}

export default Signatures;
