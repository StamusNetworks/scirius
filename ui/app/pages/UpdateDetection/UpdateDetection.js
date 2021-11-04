import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const UpdateDetection = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Management',
        <Link app to='management/update-detection'>Update Detection</Link>,
      ]}
    />
    UpdateDetection
  </div>
);
UpdateDetection.metadata = {
  position: 0,
  category: LeftNavMap.MANAGEMENT,
  url: 'management/update-detection'
}

export default UpdateDetection;
