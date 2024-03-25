import { Layout } from 'antd';
import styled from 'styled-components';

const { Sider } = Layout;

export const LeftNavStyled = styled(Sider)`
  background: #fff;
  min-height: calc(100vh - 40px);

  & * {
    /*decrease height of menus*/
    margin: 0 !important;
  }

  & svg {
    height: 22px;
    width: 22px;
  }

  .ant-menu {
    background: #fff;
  }

  .ant-menu-submenu-title {
    padding-left: 10px !important;
    padding-right: 0px !important;
    text-transform: uppercase;
    font-weight: bold;
  }

  .ant-menu-submenu-title > i {
    display: none;
  }

  .ant-menu-title-content {
    display: flex;
    align-items: center;
  }

  .anticon {
    margin-right: 3px !important;
  }

  .ant-menu-submenu-title .anticon > svg,
  .ant-menu-title-content {
    fill: rgb(0, 87, 146);
    color: rgb(0, 87, 146);
  }

  .ant-menu-item {
    padding-left: 40px !important;
    padding-right: 5px !important;
    /*decrease height of menus*/
    height: 30px !important;
    line-height: 30px !important;
  }

  & .ant-menu-title-content {
    z-index: 1;
  }

  .ant-menu-item:hover {
    background: #f0f2f5;
  }

  .ant-menu-item:hover .left-nav-link svg {
    visibility: visible;
    opacity: 1;
  }
`;

export const LeftNavLink = styled.a`
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  & svg {
    height: 16px;
    visibility: hidden;
    opacity: 0;
    transition: all 0.2s;
  }
`;
