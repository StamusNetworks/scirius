import React from 'react';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

import SignaturesPage from './SignaturesPage';

const Signatures = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to="hunting/signatures">
          Signatures
        </Link>,
      ]}
    />
    <SignaturesPage />
  </div>
);
Signatures.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/signatures',
  position: 2,
};

export default Signatures;
