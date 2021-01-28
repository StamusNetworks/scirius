import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import { makeSelectAlertTag, makeSelectGlobalFilters } from '../App/stores/global';
import { makeSelectFilterParams } from '../App/stores/filterParams';
import { HuntDashboard } from './DashboardPage';
import { withPermissions } from '../App/stores/withPermissions';

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  alertTag: makeSelectAlertTag(),
  filterParams: makeSelectFilterParams(),
});

const withConnect = connect(mapStateToProps);
export default compose(withPermissions, withConnect)(HuntDashboard);
