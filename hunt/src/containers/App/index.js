import { compose } from 'redux';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import injectReducer from '../../util/injectReducer';
import { makeSelectFilterParams, filterParamsSet, reducer } from './stores/filterParams';
import App from './App';

const mapDispatchToProps = (dispatch) => ({
    filterParamsSet: (paramName, paramValue) => dispatch(filterParamsSet(paramName, paramValue))
});

const mapStateToProps = createStructuredSelector({
    filterParams: makeSelectFilterParams(),
});

const withConnect = connect(mapStateToProps, mapDispatchToProps);
const withReducer = injectReducer({ key: 'filterParams', reducer });

export default compose(withReducer, withConnect)(App);
export { mapDispatchToProps };
