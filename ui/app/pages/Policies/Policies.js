import React from 'react';
import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import PoliciesPage from './PoliciesPage';

const Policies = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to="hunting/policies">
          Policies
        </Link>,
      ]}
    />
    <PoliciesPage />
  </div>
);
Policies.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/policies',
  position: 4,
};

export default Policies;
