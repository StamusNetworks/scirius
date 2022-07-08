import React from 'react';
import { Collapse } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const CollapseStyled = styled(Collapse)`
  margin-top: 10px;
  margin-bottom: 10px;
`;

const UICollapse = ({ children, ...props }) => <CollapseStyled {...props}>{children}</CollapseStyled>;

UICollapse.propTypes = {
  children: PropTypes.any,
};

export default UICollapse;
