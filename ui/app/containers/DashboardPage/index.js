import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { withPermissions } from 'ui/containers/HuntApp/stores/withPermissions';
import { makeSelectAlertTag, makeSelectGlobalFilters } from '../HuntApp/stores/global';
import { HuntDashboard } from './DashboardPage';

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  alertTag: makeSelectAlertTag(),
  filterParams: makeSelectFilterParams(),
});

const withConnect = connect(mapStateToProps);
export default compose(withPermissions, withConnect)(HuntDashboard);
