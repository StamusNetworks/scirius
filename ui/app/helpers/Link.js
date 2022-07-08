import React from 'react';
import PropTypes from 'prop-types';
import { Link as RouterLink } from 'react-router-dom';
import { omit } from 'lodash';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import selectors from 'ui/containers/App/selectors';
import { getQueryObject } from 'ui/helpers/getQueryObject';
import { parseObjectToUrl } from 'ui/helpers/parseObjectToUrl';
import { APP_URL } from 'ui/config';

const CustomLink = props => {
  const { app, to, replaceParams, extendParams } = props;
  let params = {};
  const appUrl = app ? `${APP_URL}/` : '';
  params = getQueryObject();
  if (params.status) delete params.status;
  if ((replaceParams || extendParams) && !(replaceParams && extendParams)) {
    if (extendParams) {
      params = { ...params, ...extendParams };
      // Filter all falsy values ( "", 0, false, null, undefined )
      // eslint-disable-next-line no-return-assign
      params = Object.entries(params).reduce((a, [k, v]) => (v ? ((a[k] = v), a) : a), {});
    } else if (replaceParams) {
      params = { ...replaceParams };
    }
  }
  const search = parseObjectToUrl(params);
  const questionMark = search.length > 0 ? '?' : '';
  return (
    <RouterLink
      {...omit(props, 'app', 'filterParam', 'dispatch', 'eventKey', 'extendParams', 'replaceParams')}
      to={`${appUrl}${to}${questionMark}${search}`}
    />
  );
};

CustomLink.defaultTypes = {
  app: false,
};

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

export const Link = withConnect(CustomLink);
