import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import rulesSelectors from 'ui/stores/filters/selectors';
import { sections } from 'ui/constants';
import { makeSelectGlobalFilters } from 'ui/containers/HuntApp/stores/global';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { withPermissions } from 'ui/containers/HuntApp/stores/withPermissions';
import { SignaturesPage } from './SignaturesPage';

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  filterParams: makeSelectFilterParams(),
  rulesets: rulesSelectors.makeSelectRuleSets(),
  rulesFilters: rulesSelectors.makeSelectFilterOptions(sections.GLOBAL),
});

const withConnect = connect(mapStateToProps);
export default compose(withConnect, withPermissions)(SignaturesPage);
