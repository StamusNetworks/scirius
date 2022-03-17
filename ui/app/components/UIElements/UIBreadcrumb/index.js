import React from 'react';
import { Breadcrumb } from 'antd';
import { PropTypes } from 'prop-types';
import styled from 'styled-components';

const StyledBreadcrumb = styled(Breadcrumb)`
  cursor: default;
  text-transform: uppercase;
  height: 30px;
  padding: 10px 20px;
  margin-bottom: 15px;
  margin-left: -20px;
  margin-right: -20px;
`;

const UIBreadcrumb = ({ items, children }) => (
  <StyledBreadcrumb separator=">">
    {!items && children}
    {/* eslint-disable-next-line react/no-array-index-key */}
    {!children && items.map((item, i) => (<Breadcrumb.Item key={i}>{item}</Breadcrumb.Item>))}
    {items && children && (<Breadcrumb.Item>items and children props can&quot;t be used together</Breadcrumb.Item>)}
  </StyledBreadcrumb>
)

UIBreadcrumb.propTypes = {
  items: PropTypes.array,
  children: PropTypes.object,
};

export default UIBreadcrumb;
