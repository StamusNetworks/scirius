import { connect } from 'react-redux';
import { compose } from 'redux';
import { createStructuredSelector } from 'reselect';

import injectReducer from '../../util/injectReducer';
import injectSaga from '../../util/injectSaga';
import { actionTypes } from './actions';
import { makeSelectActionTypesList, makeSelectHistoryList } from './selectors';
import { makeSelectHistoryFilters } from '../HuntApp/stores/global';
import reducer from './reducer';
import saga from './saga';

import HistoryPage from './HistoryPage';

const mapDispatchToProps = (dispatch) => ({
  getActionTypes: () => dispatch(actionTypes()),
});

const mapStateToProps = createStructuredSelector({
  actionTypesList: makeSelectActionTypesList(),
  historyList: makeSelectHistoryList(),
  filters: makeSelectHistoryFilters(),
});

const withConnect = connect(mapStateToProps, mapDispatchToProps);

const withReducer = injectReducer({ key: 'history', reducer });
const withSaga = injectSaga({ key: 'history', saga });

export default compose(withReducer, withSaga, withConnect)(HistoryPage);
export { mapDispatchToProps };
