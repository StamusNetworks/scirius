import React from 'react';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

import EventsPage from './EventsPage';

const Events = () => (
  <div>
    <UIBreadcrumb
      items={[
        'Hunting',
        <Link app to="hunting/events">
          Events
        </Link>,
      ]}
    />
    <EventsPage />
  </div>
);
Events.metadata = {
  category: 'STAMUS_ND',
  url: 'hunting/events',
  position: 1,
};

export default Events;
