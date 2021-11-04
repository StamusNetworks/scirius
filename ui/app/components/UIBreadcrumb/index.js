import React from 'react';
import { Breadcrumb } from 'antd';
import { PropTypes } from 'prop-types';
import styled from 'styled-components';

const StyledBreadcrumb = styled(Breadcrumb)`
  cursor: default;
`;

const UIBreadcrumb = ({ items, children }) => (
  <StyledBreadcrumb>
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
