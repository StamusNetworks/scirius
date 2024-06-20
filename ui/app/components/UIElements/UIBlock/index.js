import React from 'react';

import PropTypes from 'prop-types';
import styled from 'styled-components';

const Title = styled.h2`
  margin-bottom: 0.5rem;
  font-size: ${({ $pageTitle }) => ($pageTitle ? '2rem' : '1.25rem')};
`;

const UIBlock = ({ title, description, style, children, pageTitle }) => (
  <div style={style || {}}>
    {title && <Title $pageTitle={pageTitle}>{title}</Title>}
    {description && <p>{description}</p>}
    {children}
  </div>
);

UIBlock.propTypes = {
  title: PropTypes.string,
  description: PropTypes.string,
  style: PropTypes.object,
  children: PropTypes.any,
  pageTitle: PropTypes.bool,
};

export default UIBlock;
