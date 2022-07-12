import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { makeSelectFilterParam } from './stores/filterParams';
import HuntApp from './App';

const mapStateToProps = createStructuredSelector({
  filterParamHash: makeSelectFilterParam('hash'),
  filterParamFromDate: makeSelectFilterParam('fromDate'),
  filterParamToDate: makeSelectFilterParam('toDate'),
  duration: makeSelectFilterParam('duration'),
});

export default connect(mapStateToProps)(HuntApp);
