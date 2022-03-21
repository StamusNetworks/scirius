import React from 'react';
import { PAGE_STATE } from 'constants';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const Policies = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='stamus/hunting/policies'>Policies</Link>,
      ]}
    />
    Policies
    <HuntApp page={PAGE_STATE.filters_list} />
  </div>
);
Policies.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus/hunting/policies',
}

export default Policies;
