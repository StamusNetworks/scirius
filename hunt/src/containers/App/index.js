import { connect } from 'react-redux';
import { compose } from 'redux';
import { createStructuredSelector } from 'reselect';
import injectReducer from '../../util/injectReducer';
import { filterParamsSet, makeSelectFilterParam, reducer, reload } from './stores/filterParams';
import App from './App';
import { withPermissions } from './stores/withPermissions';
import injectSaga from '../../util/injectSaga';
import saga from './stores/global.saga';
import { getUserDetails } from './stores/global';

const mapStateToProps = createStructuredSelector({
  filterParamHash: makeSelectFilterParam('hash'),
  filterParamFromDate: makeSelectFilterParam('fromDate'),
  filterParamToDate: makeSelectFilterParam('toDate'),
  duration: makeSelectFilterParam('duration'),
});

const mapDispatchToProps = (dispatch) => ({
  filterParamsSet: (paramName, paramValue) => dispatch(filterParamsSet(paramName, paramValue)),
  reload: () => dispatch(reload()),
  getUserDetails: () => dispatch(getUserDetails()),
});

const withConnect = connect(mapStateToProps, mapDispatchToProps);
const withReducer = injectReducer({ key: 'filterParams', reducer });
const withSaga = injectSaga({ key: 'global', saga });

export default compose(withSaga, withReducer, withConnect, withPermissions)(App);
