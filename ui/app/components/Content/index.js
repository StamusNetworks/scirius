import React from 'react';

import { Layout } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const { Content: AntdContent } = Layout;

const StyledOuterWrapper = styled(AntdContent)`
  padding: 0 20px 20px 20px;
`;

const Content = ({ children }) => <StyledOuterWrapper>{children}</StyledOuterWrapper>;

Content.propTypes = {
  children: PropTypes.any,
};

export default Content;
