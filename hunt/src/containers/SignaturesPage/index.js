import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import { makeSelectGlobalFilters } from '../App/stores/global';
import { makeSelectFilterParams } from '../App/stores/filterParams';
import { SignaturesPage } from './SignaturesPage';
import { withPermissions } from '../App/stores/withPermissions';

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  filterParams: makeSelectFilterParams(),
});

const withConnect = connect(mapStateToProps);
export default compose(withConnect, withPermissions)(SignaturesPage);
