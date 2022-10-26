import React from 'react';
import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import PoliciesPage from './PoliciesPage';
import UpdatePushRuleset from '../../components/UpdatePushRuleset';

const Policies = () => (
  <div>
    <div style={{ display: 'flex', flex: 1, justifyContent: 'space-between', alignItems: 'center' }}>
      <UIBreadcrumb
        items={[
          'Hunting',
          <Link app to="hunting/policies">
            Policies
          </Link>,
        ]}
      />
      <UpdatePushRuleset />
    </div>
    <PoliciesPage />
  </div>
);
Policies.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/policies',
  position: 4,
};

export default Policies;
