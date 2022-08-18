import styled from 'styled-components';
import { Layout } from 'antd';
import { Link } from 'react-router-dom';
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
      fill: transparent;
      stroke: currentColor;
      stroke-width: 2;
      margin-right: 5px;
    }
  }

  & .ant-menu {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    height: 100%;
    background-color: rgb(0, 87, 146);
  }

  & .ant-menu-item {
    padding: 0 !important;
    border-right: 1px solid #00426e !important;
    border-left: 1px solid #226b9d !important;
    transition: all 0.3s;

    &:first-child:after {
      border-right: 1px solid #00426e !important;
      height: 100%;
      width: 1px;
      left: -2px;
    }

    &:hover {
      background: #004d80 !important;
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

  & img {
    height: 30px;
    padding-bottom: 3px;
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
