import React from 'react';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { compose } from 'redux';
import { makeSelectUserData, makeSelectUserRequest } from './global';

export const withPermissions = (WrappedComponent) => {
  const Enhancer = (props) => <WrappedComponent {...props} />;
  const mapStateToProps = createStructuredSelector({
    user: makeSelectUserData(),
    userRequest: makeSelectUserRequest(),
  });
  const withConnect = connect(mapStateToProps);
  return compose(withConnect)(Enhancer);
};
