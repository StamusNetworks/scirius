import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import { addFilter, makeSelectGlobalFilters } from '../App/stores/global';
import { makeSelectFilterParams } from '../App/stores/filterParams';
import { AlertsPage } from './AlertsPage';
import { withPermissions } from '../App/stores/withPermissions';

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
