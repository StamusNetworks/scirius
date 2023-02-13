import React from 'react';
import { Card } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import { COLOR_BRAND_BLUE } from 'ui/constants/colors';

const CardStyled = styled(Card).withConfig({
  shouldForwardProp: prop => !['fullHeight', 'noPadding'].includes(prop),
})`
  background-color: white;
  border-radius: 5px;
  position: relative;
  box-shadow: ${p => (!p.flat ? '2px 3px 6px 0px #00000005' : 'none')};
  border: 1px solid #ececec;
  height: ${p => (p.fullHeight === 'true' ? '100%' : 'auto')};
  .ant-card-body {
    padding: ${p => (p.noPadding === 'true' ? '0' : '10px')};
  }
  .ant-card-head {
    padding: 0 10px;
    min-height: 40px;
  }
  .ant-card-head-title,
  .ant-card-extra {
    padding: 7px 0;
  }
  .ant-card-head-title {
    color: ${p => p.color};
  }
  ${p => (p.flex ? "display: 'flex'; flex: 1; flex-direction: 'column';" : '')}
`;
const UICard = ({ children, noPadding, fullHeight, ...props }) => (
  <CardStyled {...props} noPadding={noPadding.toString()} fullHeight={fullHeight.toString()}>
    {children}
  </CardStyled>
);

UICard.defaultProps = {
  noPadding: false,
  fullHeight: false,
  color: COLOR_BRAND_BLUE,
};

UICard.propTypes = {
  children: PropTypes.any,
  noPadding: PropTypes.bool,
  fullHeight: PropTypes.bool,
  color: PropTypes.string,
};

export default UICard;
