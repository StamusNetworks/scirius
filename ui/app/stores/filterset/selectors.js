import { createSelector } from 'reselect';
import { initialState } from './reducer';

const makeSelectFiltersSetsStore = state => state.filterSets || initialState;
const makeSelectGlobalFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.data.filter(f => f.share === 'global'));
const makeSelectPrivateFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.data.filter(f => f.share === 'private'));
const makeSelectStaticFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.data.filter(f => f.share === 'static'));
const makeSelectFilterSetsRequest = type => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.request[type]);
const makeSelectDeleteFilterSetId = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.request.delete.confirmId);

export default {
  makeSelectGlobalFilterSets,
  makeSelectPrivateFilterSets,
  makeSelectStaticFilterSets,
  makeSelectFilterSetsRequest,
  makeSelectDeleteFilterSetId,
};
