import React from 'react';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const Signatures = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='stamus/hunting/signatures'>Signatures</Link>,
      ]}
    />
    Signatures
  </div>
);
Signatures.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus/hunting/signatures',
}

export default Signatures;
