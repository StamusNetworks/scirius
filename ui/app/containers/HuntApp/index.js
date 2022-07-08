import { connect } from 'react-redux';
import { compose } from 'redux';
import { createStructuredSelector } from 'reselect';
import injectReducer from 'ui/utils/injectReducer';
import { filterParamsSet, makeSelectFilterParam, reducer, reload } from './stores/filterParams';
import HuntApp from './App';
import { withPermissions } from './stores/withPermissions';

const mapStateToProps = createStructuredSelector({
  filterParamHash: makeSelectFilterParam('hash'),
  filterParamFromDate: makeSelectFilterParam('fromDate'),
  filterParamToDate: makeSelectFilterParam('toDate'),
  duration: makeSelectFilterParam('duration'),
});

const mapDispatchToProps = dispatch => ({
  filterParamsSet: (paramName, paramValue) => dispatch(filterParamsSet(paramName, paramValue)),
  reload: () => dispatch(reload()),
});

const withConnect = connect(mapStateToProps, mapDispatchToProps);
const withReducer = injectReducer({ key: 'filterParams', reducer });

export default compose(withReducer, withConnect, withPermissions)(HuntApp);
