import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { addFilter, makeSelectGlobalFilters } from '../App/stores/global';
import { makeSelectFilterParams } from '../App/stores/filterParams';
import { AlertsPage } from './AlertsPage';

const mapStateToProps = createStructuredSelector({
    filters: makeSelectGlobalFilters(),
    filtersWithAlert: makeSelectGlobalFilters(true),
    filterParams: makeSelectFilterParams(),
});

const mapDispatchToProps = {
    addFilter,
}

export default connect(mapStateToProps, mapDispatchToProps)(AlertsPage);
