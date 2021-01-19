import { connect } from 'react-redux';
import { compose } from 'redux';
import { createStructuredSelector } from 'reselect';

import injectReducer from '../../util/injectReducer';
import injectSaga from '../../util/injectSaga';
import {
  filterSetsReducer as reducer,
  filterSetsSaga as saga,
  loadFilterSets,
  deleteFilterSet,
  makeSelectFilterSetsLoading,
  makeSelectStaticFilterSets,
  makeSelectPrivateFilterSets,
  makeSelectGlobalFilterSets,
} from './store';

import FilterSets from './FilterSets';
import { addFilter, clearFilters, setTag } from '../../containers/App/stores/global';

const mapDispatchToProps = (dispatch) => ({
  addFilter: (filterType, filter) => dispatch(addFilter(filterType, filter)),
  clearFilters: (filterType) => dispatch(clearFilters(filterType)),
  loadFilterSets: () => dispatch(loadFilterSets()),
  deleteFilterSet: (filterType, filter) => dispatch(deleteFilterSet(filterType, filter)),
  setTag: (tagType, tagState) => dispatch(setTag(tagType, tagState)),
});

const mapStateToProps = createStructuredSelector({
  globalSet: makeSelectGlobalFilterSets(),
  privateSet: makeSelectPrivateFilterSets(),
  staticSet: makeSelectStaticFilterSets(),
  loading: makeSelectFilterSetsLoading(),
});

const withConnect = connect(mapStateToProps, mapDispatchToProps);

const withReducer = injectReducer({ key: 'filterSets', reducer });
const withSaga = injectSaga({ key: 'filterSets', saga });

export default compose(withReducer, withSaga, withConnect)(FilterSets);
export { mapDispatchToProps };
