import React from 'react';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { compose } from 'redux';
import { makSelectUserData, makSelectUserRequest } from './global';

export const withPermissions = (WrappedComponent) => {
  const Enhancer = (props) => <WrappedComponent {...props} />;
  const mapStateToProps = createStructuredSelector({
    user: makSelectUserData(),
    userRequest: makSelectUserRequest(),
  });
  const withConnect = connect(mapStateToProps);
  return compose(withConnect)(Enhancer);
};
