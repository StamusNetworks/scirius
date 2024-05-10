import { FilterCategory } from 'ui/maps/Filters';
import Filter from 'ui/utils/Filter';

export const createFilterInstanceFromStorage = ({ id, value, negated, fullString, uuid }) => {
  if (id.startsWith('alert.metadata')) {
    const lowerTitle = id.split('.')[2]?.replace('_', ' ');
    const title = lowerTitle[0].toUpperCase() + lowerTitle.slice(1);
    return new Filter(id, value, FilterCategory.EVENT, { title, uuid, negated, fullString });
  }

  return new Filter(id, value, { uuid, negated, fullString });
};

export const getEventTypesToTurnOn = filters => {
  const eventTypesToTurnOn = filters.map(filter => filter.force || []).flat();
  const uniqueEventTypes = [...new Set(eventTypesToTurnOn)];

  return uniqueEventTypes;
};
