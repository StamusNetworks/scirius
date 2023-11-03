import _ from 'lodash';

export const getTitle = (protoMap, key, events) =>
  `Related ${protoMap[key] || _.capitalize(events[key][0].rawJson.event_type)}${key === 'Alert' && Object.keys(events[key]).length > 1 ? 's' : ''}`;
