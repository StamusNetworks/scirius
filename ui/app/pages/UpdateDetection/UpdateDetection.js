import React from 'react';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import UIBreadcrumb from 'ui/components/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

const UpdateDetection = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Stamus ND',
        <Link app to='stamus-nd/update-detection'>Update Detection</Link>,
      ]}
    />
    UpdateDetection
  </div>
);
UpdateDetection.metadata = {
  position: 0,
  category: LeftNavMap.STAMUS_ND,
  url: 'stamus-nd/update-detection'
}

export default UpdateDetection;
