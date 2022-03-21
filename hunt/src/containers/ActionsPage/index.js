import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { makeSelectFilterParams } from '../HuntApp/stores/filterParams';
import { ActionsPage } from './ActionsPage';

const mapStateToProps = createStructuredSelector({
  filterParams: makeSelectFilterParams(),
});

export default connect(mapStateToProps)(ActionsPage);
