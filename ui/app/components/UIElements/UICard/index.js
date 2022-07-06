import React from 'react';
import { Card } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const CardStyled = styled(Card)`
  background-color: white;
  border-radius: 5px;
  position: relative;
  box-shadow: ${p => !p.flat ? '2px 3px 6px 0px #00000005' : 'none'};
  border: 1px solid #ececec;
  .ant-card-body {
    padding: ${p => p.nopadding === 'true' ? '0' : '10px'};
  }
  .ant-card-head {
    padding: 0 10px;
    min-height: 40px;
  }
  .ant-card-head-title,
  .ant-card-extra {
    padding: 7px 0;
  }
`;
const UICard = ({ children, noPadding, ...props }) => (
    <CardStyled {...props} nopadding={noPadding.toString()}>
      {children}
    </CardStyled>
  )

UICard.defaultProps = {
  noPadding: false,
}

UICard.propTypes = {
  children: PropTypes.any,
  noPadding: PropTypes.bool,
}

export default UICard;
