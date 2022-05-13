import selectors from 'ui/containers/App/selectors';

export const getMap = state => ({
  ':filters': selectors.makeSelectFilters()(state),
  ':dates': selectors.makeSelectURLDates(state),
  ':datesEs': selectors.makeSelectURLDatesES(state),
});
