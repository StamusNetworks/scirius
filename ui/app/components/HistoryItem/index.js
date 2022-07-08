import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { addFilter } from 'ui/containers/HuntApp/stores/global';

const HistoryItem = props => (
  <>
    {props.data.comment && (
      <>
        <strong>Comment</strong>
        <div>{props.data.comment}</div>
      </>
    )}
    {props.data.client_ip && (
      <>
        <strong>IP</strong>
        <div>{props.data.client_ip}</div>
      </>
    )}
  </>
);
HistoryItem.propTypes = {
  data: PropTypes.any,
};

const mapDispatchToProps = {
  addFilter,
};

export default connect(null, mapDispatchToProps)(HistoryItem);
