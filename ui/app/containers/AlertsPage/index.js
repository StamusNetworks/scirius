import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import { addFilter, makeSelectGlobalFilters } from '../HuntApp/stores/global';
import { makeSelectFilterParams } from '../HuntApp/stores/filterParams';
import { AlertsPage } from './AlertsPage';
import { withPermissions } from '../HuntApp/stores/withPermissions';

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  filterParams: makeSelectFilterParams(),
});

const mapDispatchToProps = {
  addFilter,
};

const withConnect = connect(mapStateToProps, mapDispatchToProps);
export default compose(withConnect, withPermissions)(AlertsPage);
