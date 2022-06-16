import React from 'react';
import { Collapse } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const { Panel } = Collapse;

const PanelStyled = styled(Panel)`
  border-bottom: 1px solid #bcccd1 !important;
  transition: all 0.2s;

  &:hover {
    background: #f0f2f5;
    box-shadow: 0 5px 10px #dbdcdf;
  }
  .ant-collapse-header {
    display: flex;
  }
  .ant-collapse-header[aria-expanded="true"] {
    background: #bcccd1;
  }
  &.ant-collapse-item-active {
    border: #bcccd1 1px solid;
    border-image: linear-gradient( 180deg, #bcccd1 0%, #005792 100% ) 0 100%;
    border-top-width: 0px;
    outline: solid 1px #bcccd1;
  }
  .ant-collapse-extra {
    display: grid;
    grid-template-columns: max-content repeat(2, min-content);
    align-items: center;
  }
`;

const UIPanel = ({ children, ...props }) => (
    <PanelStyled {...props}>
      {children}
    </PanelStyled>
  )

UIPanel.propTypes = {
  children: PropTypes.any,
}

export default UIPanel;
