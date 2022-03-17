import React from 'react';
import { Card } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const CardStyled = styled(Card)`
  background-color: white;
  border-radius: 5px;
  position: relative;
  box-shadow: ${p => !p.flat ? '3px 3px 10px #c9c9c9' : 'none'};
`;

const UICard = ({ children, ...props }) => (
    <CardStyled {...props}>
      {children}
    </CardStyled>
  )

UICard.propTypes = {
  children: PropTypes.object,
}

export default UICard;
