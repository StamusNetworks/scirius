import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import selectors from 'ui/containers/App/selectors';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { ActionsPage } from './ActionsPage';

const mapStateToProps = createStructuredSelector({
  filterParams: makeSelectFilterParams(),
  multiTenancy: selectors.makeSelectMultiTenancy(),
});

export default connect(mapStateToProps)(ActionsPage);
