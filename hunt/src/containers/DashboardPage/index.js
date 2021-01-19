import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { makeSelectAlertTag, makeSelectGlobalFilters } from '../App/stores/global';
import { makeSelectFilterParams } from '../App/stores/filterParams';
import { HuntDashboard } from './DashboardPage';

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  alertTag: makeSelectAlertTag(),
  filterParams: makeSelectFilterParams(),
});

export default connect(mapStateToProps)(HuntDashboard);
