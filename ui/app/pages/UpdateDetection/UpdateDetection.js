import React from 'react';
import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const UpdateDetection = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Stamus ND',
        <Link app to="stamus-nd/update-detection">
          Update Detection
        </Link>,
      ]}
    />
    UpdateDetection
  </div>
);
UpdateDetection.metadata = {
  category: 'STAMUS_ND',
  url: 'stamus-nd/update-detection',
};

export default UpdateDetection;
