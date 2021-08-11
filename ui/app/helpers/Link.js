import React from 'react';
import PropTypes from 'prop-types';
import { Link as RouterLink } from 'react-router-dom';
import history from 'utils/history';
import { omit } from 'lodash';
import { createStructuredSelector } from 'reselect';
import { compose } from 'redux';
import { connect } from 'react-redux';
import { makeSelectFiltersParam } from 'ui/containers/App/selectors';
import { getQueryObject } from './getQueryObject';
import { parseObjectToUrl } from './parseObjectToUrl';

const CustomLink = props => {
  const { to, replaceParams, extendParams } = props;
  let { search } = history.location;
  let params = {};
  let questionMark = '';
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
  return <RouterLink {...omit(props, 'filterParam', 'dispatch', 'eventKey', 'extendParams', 'replaceParams')} to={`${to}${questionMark}${search}`} />;
};

CustomLink.propTypes = {
  to: PropTypes.string,
  replaceParams: PropTypes.object,
  extendParams: PropTypes.object,
};

const mapStateToProps = createStructuredSelector({
  filterParam: makeSelectFiltersParam(),
});

const withConnect = connect(mapStateToProps);

export const Link = compose(withConnect)(CustomLink);
