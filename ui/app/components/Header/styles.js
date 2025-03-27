import { Layout } from 'antd';
import { Link } from 'react-router-dom';
import styled from 'styled-components';

import { COLOR_ANT_MENU } from 'ui/constants/colors';

const { Header } = Layout;

export const HeaderStyled = styled(Header)`
  background: ${COLOR_ANT_MENU};
  padding: 0;
  height: 40px;
  line-height: 40px;

  .tenant-dropdown {
    & i {
      font-size: 20px;
      margin-right: 7px;
    }
  }

  .timerange-dropdown {
    & svg {
      height: 22px;
      width: 22px;
      margin-right: 5px;
    }
  }

  .help-dropdown,
  .reload-dropdown {
    & svg {
      height: 22px;
      width: 22px;
    }
  }

  .user-dropdown {
    & svg {
      width: 22px;
      height: 22px;
    }
  }

  & .ant-menu {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    height: 100%;
    background-color: ${COLOR_ANT_MENU};
  }

  & .ant-menu-item:hover {
    backdrop-filter: brightness(0.85) !important;
  }

  & .ant-menu-item {
    padding: 0 !important;
    border-right: 1px solid rgba(0, 0, 0, 0.2) !important;
    border-left: 1px solid rgba(255, 255, 255, 0.15) !important;
    transition: all 0.1s;
    position: relative;

    &:first-child:after {
      border-right: 1px solid rgba(0, 0, 0, 0.2) !important;
      height: 100%;
      width: 1px;
      left: -2px;
    }
  }

  & .ant-menu-title-content > span {
    display: flex;
    align-items: center;
    height: 100%;
    padding: 0 20px;
  }

  & .ant-menu-title-content > span > span {
    display: flex;
    align-items: center;
    margin-right: 5px;
  }
`;

export const Logo = styled(Link)`
  float: left;
  padding-left: 14px;

  height: 100%;
  display: flex;
  align-items: center;

  & img {
    max-height: 30px;
    padding-bottom: 3px;

    & + img {
      margin-left: 0.5rem;
    }
  }
`;

export const RangePreview = styled.table`
  font-size: 12px;
  border: 0;
  & td {
    border: 0;
  }
  & td.col {
    padding-right: 10px;
    text-align: right;
  }
  & td.col::after {
    display: inline-block;
    content: ':';
  }
`;
