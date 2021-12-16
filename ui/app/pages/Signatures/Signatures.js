import React from 'react';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const Signatures = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Stamus ND',
        <Link app to='stamus-nd/signatures'>Signatures</Link>,
      ]}
    />
    Signatures
  </div>
);
Signatures.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus-nd/signatures',
}

export default Signatures;
