import { createSelector } from 'reselect';
import { initialState } from './reducer';

const makeSelectFiltersSetsStore = state => state.filterSets || initialState;
const makeSelectGlobalFilterSets = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.filterSets.global);
const makeSelectPrivateFilterSets = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.filterSets.private);
const makeSelectStaticFilterSets = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.filterSets.static);
const makeSelectFilterSetsLoading = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.filterSetsLoading);

export default {
  makeSelectGlobalFilterSets,
  makeSelectPrivateFilterSets,
  makeSelectStaticFilterSets,
  makeSelectFilterSetsLoading,
};
