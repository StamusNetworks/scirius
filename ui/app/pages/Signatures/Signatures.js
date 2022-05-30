import React from 'react';
import { PAGE_STATE } from 'constants';
import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const Signatures = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/signatures'>Signatures</Link>,
      ]}
    />
    <HuntApp page={PAGE_STATE.rules_list} />
  </div>
);
Signatures.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/signatures',
}

export default Signatures;
