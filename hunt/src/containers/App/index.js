import { connect } from 'react-redux';
import { compose } from 'redux';
import injectReducer from '../../util/injectReducer';
import { filterParamsSet, reducer } from './stores/filterParams';
import App from './App';

const mapDispatchToProps = (dispatch) => ({
    filterParamsSet: (paramName, paramValue) => dispatch(filterParamsSet(paramName, paramValue)),
});

const withConnect = connect(null, mapDispatchToProps);
const withReducer = injectReducer({ key: 'filterParams', reducer });

export default compose(withReducer, withConnect)(App);
