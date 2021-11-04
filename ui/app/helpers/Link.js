import React from 'react';
import PropTypes from 'prop-types';
import { Link as RouterLink } from 'react-router-dom';
import history from 'utils/history';
import { omit } from 'lodash';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import { connect } from 'react-redux';
import selectors from 'ui/containers/App/selectors';
import { getQueryObject } from './getQueryObject';
import { parseObjectToUrl } from './parseObjectToUrl';
import { APP_URL } from '../config';

const CustomLink = props => {
  const { app, to, replaceParams, extendParams } = props;
  let { search } = history.location;
  let params = {};
  let questionMark = '';
  const appUrl = app ? `${APP_URL}/` : '';
  if ((replaceParams || extendParams) && !(replaceParams && extendParams)) {
    if (extendParams) {
      params = getQueryObject();
      params = { ...params, ...extendParams };
      // Filter all falsy values ( "", 0, false, null, undefined )
      // eslint-disable-next-line no-return-assign
      params = Object.entries(params).reduce((a, [k, v]) => (v ? ((a[k] = v), a) : a), {});
    } else if (replaceParams) {
      params = { ...replaceParams };
    }
    questionMark = '?';
    search = parseObjectToUrl(params);
  }
  return <RouterLink {...omit(props, 'app', 'filterParam', 'dispatch', 'eventKey', 'extendParams', 'replaceParams')} to={`${appUrl}${to}${questionMark}${search}`} />;
};

CustomLink.defaultTypes = {
  app: false,
}

CustomLink.propTypes = {
  app: PropTypes.bool,
  to: PropTypes.string,
  replaceParams: PropTypes.object,
  extendParams: PropTypes.object,
};

const mapStateToProps = createStructuredSelector({
  filterParam: selectors.makeSelectFiltersParam(),
});

const withConnect = connect(mapStateToProps);

export const Link = compose(withConnect)(CustomLink);
