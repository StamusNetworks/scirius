import React from 'react';

import moment from 'moment';
import PropTypes from 'prop-types';

export const XAxisLabelDateTime = ({ x, y, payload }) => {
  const day = moment(payload?.value).format('ll');
  const time = moment(payload?.value).format('LT');
  return (
    <g transform={`translate(${x},${y})`} fontSize={10}>
      <text x={0} y={0} dy={12} textAnchor="middle" fill="#666">
        {day}
      </text>
      <text x={0} y={12} dy={12} textAnchor="middle" fill="#666">
        {time}
      </text>
    </g>
  );
};

XAxisLabelDateTime.propTypes = {
  x: PropTypes.number.isRequired,
  y: PropTypes.number.isRequired,
  payload: PropTypes.object.isRequired,
};
