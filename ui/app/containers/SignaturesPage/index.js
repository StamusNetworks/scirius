import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import { makeSelectGlobalFilters } from '../HuntApp/stores/global';
import { makeSelectFilterParams } from '../HuntApp/stores/filterParams';
import { SignaturesPage } from './SignaturesPage';
import { withPermissions } from '../HuntApp/stores/withPermissions';

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  filterParams: makeSelectFilterParams(),
});

const withConnect = connect(mapStateToProps);
export default compose(withConnect, withPermissions)(SignaturesPage);
