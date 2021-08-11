import React from 'react';
import PropTypes from 'prop-types';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { compose } from 'redux';
import { makeSelectFamilies, makeSelectFilters, makeSelectThreats } from 'ui/containers/App/selectors';

const createFilterTag = (WrappedComponent, filter, filterValue) => {
  const HOC = ({ threats, families }) => {
    const { data: threatsData } = threats;
    const { data: familiesData } = families.list;
    const { urlParam } = filter;
    let value = '';
    let loading = false;

    if (urlParam === 'threat_id') {
      value = ((threatsData.length > 0 && threatsData.find(o => o.threat_id === filterValue)) || { name: 'n/a' }).name;
      // eslint-disable-next-line prefer-destructuring
      loading = threats.list.request.loading;
    } else if (urlParam === 'family_id') {
      value = ((familiesData.length > 0 && familiesData.find(o => o.family_id === filterValue)) || { name: 'n/a' }).name;
      // eslint-disable-next-line prefer-destructuring
      loading = families.list.request.loading;
    }

    return <WrappedComponent filter={filter} value={value} loading={loading} />;
  };

  HOC.propTypes = {
    threats: PropTypes.object,
    families: PropTypes.any,
  };

  const mapStateToProps = createStructuredSelector({
    filters: makeSelectFilters(),
    families: makeSelectFamilies(),
    threats: makeSelectThreats(),
  });
  const withConnect = connect(mapStateToProps);
  return compose(withConnect)(HOC);
};

export default createFilterTag;
