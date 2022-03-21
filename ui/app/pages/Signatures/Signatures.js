import React from 'react';
import { PAGE_STATE } from 'constants';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const Signatures = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='stamus/hunting/signatures'>Signatures</Link>,
      ]}
    />
    Signatures
    <HuntApp page={PAGE_STATE.rules_list} />
  </div>
);
Signatures.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus/hunting/signatures',
}

export default Signatures;
