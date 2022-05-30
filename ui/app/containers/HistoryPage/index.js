import { connect } from 'react-redux';
import { compose } from 'redux';
import { createStructuredSelector } from 'reselect';

import injectReducer from 'ui/utils/injectReducer';
import injectSaga from 'ui/utils/injectSaga';
import filtersActions from 'ui/stores/filters/actions';
import reducer from 'ui/stores/filters/reducer';
import saga from 'ui/stores/filters/saga';
import { addFilter , makeSelectHistoryFilters } from 'ui/containers/HuntApp/stores/global';

import HistoryPage from './HistoryPage';

const mapDispatchToProps = (dispatch) => ({
  getActionTypes: () => dispatch(filtersActions.historyFiltersRequest()),
  addFilter,
});

const mapStateToProps = createStructuredSelector({
  filters: makeSelectHistoryFilters(),
});

const withConnect = connect(mapStateToProps, mapDispatchToProps);

const withReducer = injectReducer({ key: 'filters', reducer });
const withSaga = injectSaga({ key: 'filters', saga });

export default compose(withReducer, withSaga, withConnect)(HistoryPage);
export { mapDispatchToProps };
