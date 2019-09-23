import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { makeSelectGlobalFilters } from '../App/stores/global';
import { makeSelectFilterParams } from '../App/stores/filterParams';
import { SignaturesPage } from './SignaturesPage';

const mapStateToProps = createStructuredSelector({
    filters: makeSelectGlobalFilters(),
    filtersWithAlert: makeSelectGlobalFilters(true),
    filterParams: makeSelectFilterParams()
});

export default connect(mapStateToProps)(SignaturesPage);
