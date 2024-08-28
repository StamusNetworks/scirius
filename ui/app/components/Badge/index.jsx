import React from 'react';

import { Badge as AntDBadge } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import { COLOR_ASSET_THREAT_ATTACKER_COLOR, COLOR_GREY_BADGE } from 'ui/constants/colors';
import formatNumber from 'ui/helpers/formatNumber';

const Container = styled(AntDBadge)`
  .ant-scroll-number-only-unit {
    font-weight: normal !important;
  }
`;

export const Badge = ({ count, variant }) => (
  <Container
    color={variant === 'offender' ? COLOR_ASSET_THREAT_ATTACKER_COLOR : variant === 'neutral' ? COLOR_GREY_BADGE : undefined}
    showZero
    overflowCount={1001}
    count={formatNumber(count)}
  />
);

Badge.propTypes = {
  count: PropTypes.number.isRequired,
  variant: PropTypes.oneOf(['neutral', 'victim', 'offender']),
};

Badge.defaultProps = {
  variant: 'victim',
};
