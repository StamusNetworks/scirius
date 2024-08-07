import React from 'react';

import { Empty } from 'antd';
import moment from 'moment';
import PropTypes from 'prop-types';
import { ResponsiveContainer, BarChart, Bar, CartesianGrid, YAxis, XAxis, Tooltip } from 'recharts';

import * as Style from './style';

export const Timeline = ({ chart, stacked = false, height, width, XAxisLabel }) => {
  const Wrapper = width ? React.Fragment : ResponsiveContainer;
  return (
    <Wrapper>
      {!chart.data.length > 0 ? (
        <Style.EmptyWrapper>
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
        </Style.EmptyWrapper>
      ) : (
        <BarChart height={height} width={width} data={chart.data} margin={{ bottom: 10 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <Tooltip labelFormatter={label => <TooltipLabel label={label} interval={chart.dates.interval} />} />
          {chart.keys.map(key => (
            <Bar {...key} key={key.dataKey} stackId={stacked && 'a'} />
          ))}
          <YAxis />
          <XAxis dataKey="time" tick={XAxisLabel && <XAxisLabel />} />
        </BarChart>
      )}
    </Wrapper>
  );
};

Timeline.propTypes = {
  chart: PropTypes.shape({
    data: PropTypes.array.isRequired,
    keys: PropTypes.array.isRequired,
    dates: PropTypes.shape({
      from: PropTypes.number.isRequired,
      to: PropTypes.number.isRequired,
      interval: PropTypes.number.isRequired,
    }).isRequired,
  }).isRequired,
  stacked: PropTypes.bool,
  width: PropTypes.number,
  height: PropTypes.number,
  XAxisLabel: PropTypes.func,
};

const TooltipLabel = ({ label, interval }) => {
  const from = moment(label).format('ll LT');
  const to = moment(label + interval).format('ll LT');
  return (
    <g fontSize={12}>
      <text>
        <b>From:</b> {from}
        <br />
        <b>To:</b> {to}
      </text>
    </g>
  );
};

TooltipLabel.propTypes = {
  label: PropTypes.number.isRequired,
  interval: PropTypes.number.isRequired,
};
