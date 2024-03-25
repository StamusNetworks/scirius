/* eslint-disable react/no-array-index-key */
import React from 'react';

import { Breadcrumb } from 'antd';
import { PropTypes } from 'prop-types';
import styled from 'styled-components';

const StyledBreadcrumb = styled(Breadcrumb)`
  cursor: default;
  text-transform: uppercase;
  height: 30px;
  padding: 10px 20px;
  margin: 5px -20px;
  border-bottom: 0 !important;
`;

const Container = styled.div`
  display: flex;
`;

const BreadcrumbWrapper = styled.div`
  display: flex;
  flex-direction: row;
  flex: 1;
`;

const AddonWrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 5px;
`;

const UIBreadcrumb = ({ items, addon }) => (
  <Container>
    <BreadcrumbWrapper>
      <StyledBreadcrumb separator=">">
        {items.map((item, i) => (
          <Breadcrumb.Item key={i}>{item}</Breadcrumb.Item>
        ))}
      </StyledBreadcrumb>
    </BreadcrumbWrapper>
    {addon && <AddonWrapper>{addon}</AddonWrapper>}
  </Container>
);

UIBreadcrumb.propTypes = {
  items: PropTypes.array,
  addon: PropTypes.object,
};

export default UIBreadcrumb;
