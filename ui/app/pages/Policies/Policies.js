import React from 'react';
import { PAGE_STATE } from 'constants';
import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import HuntApp from 'ui/containers/HuntApp';

const Policies = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to='hunting/policies'>Policies</Link>,
      ]}
    />
    <HuntApp page={PAGE_STATE.filters_list} />
  </div>
);
Policies.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/policies',
}

export default Policies;
