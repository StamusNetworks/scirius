import React from 'react';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

import UpdatePushRuleset from '../../components/UpdatePushRuleset';
import PoliciesPage from './PoliciesPage';

const Policies = () => (
  <div>
    <div style={{ display: 'flex', flex: 1, justifyContent: 'space-between', alignItems: 'center' }}>
      <UIBreadcrumb
        items={[
          'Hunting',
          <Link app to="hunting/policies" key="policies-link">
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
  access: permissions => permissions.includes('rules.ruleset_policy_view'),
};

export default Policies;
