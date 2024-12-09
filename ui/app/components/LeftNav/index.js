import React, { useCallback, useMemo } from 'react';

import { LinkOutlined } from '@ant-design/icons';
import { Menu, Spin } from 'antd';
import { observer } from 'mobx-react-lite';
import { useLocation, withRouter } from 'react-router-dom';

import { default as Icon } from 'ui/components/IconAntd';
import { APP_URL } from 'ui/config';
import { CamelCaseToNormal } from 'ui/helpers';
import { Link } from 'ui/helpers/Link';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import { useStore } from 'ui/mobx/RootStoreProvider';
import pages from 'ui/pages';

import { LeftNavStyled, LeftNavLink } from './styles';

const { SubMenu } = Menu;

const pagesList = Object.keys(pages);

const getGroupPages = (category, permissions, systemSettings) =>
  pagesList
    .filter(
      page =>
        pages[page].metadata &&
        pages[page].metadata.category === category &&
        (!pages[page].metadata.access || pages[page].metadata.access(permissions, systemSettings)),
    )
    .sort((a, b) => pages[a].metadata.position - pages[b].metadata.position);

function LeftNav() {
  const { commonStore } = useStore();
  const { permissions = [] } = commonStore.user || {};

  const renderMenuItems = useCallback(
    groupId =>
      getGroupPages(groupId, permissions, commonStore.systemSettings).map(page => {
        const computedTitle = pages[page].metadata.computedTitle ? pages[page].metadata.computedTitle(commonStore.systemSettings) : null;
        const title = computedTitle || pages[page].metadata.title || CamelCaseToNormal(page);
        return (
          <Menu.Item key={`${APP_URL}/${pages[page].metadata.url}`} data-test="left-nav-menu-link-item">
            {typeof pages[page].metadata.url === 'function' ? (
              <LeftNavLink href={pages[page].metadata.url(commonStore.systemSettings)} target="_blank" className="left-nav-link">
                <div>{title}</div>
                <LinkOutlined />
              </LeftNavLink>
            ) : (
              <Link to={`${APP_URL}/${pages[page].metadata.url}`}>{title}</Link>
            )}
          </Menu.Item>
        );
      }),
    [commonStore.systemSettings, permissions],
  );

  const renderSubMenus = useMemo(
    () =>
      LeftNavMap.map(group => {
        if (!commonStore.systemSettings.license?.nta && group.nta) return null;
        return (
          <SubMenu
            key={group.id}
            title={
              <React.Fragment>
                <Icon component={group.icon} />
                {group.title}
              </React.Fragment>
            }
          >
            {renderMenuItems(group.id)}
          </SubMenu>
        );
      }).filter(submenu => submenu),
    [commonStore.systemSettings, permissions],
  );

  return (
    <LeftNavStyled width={200}>
      <Menu
        mode="inline"
        selectedKeys={[useLocation().pathname.split('/').slice(0, 4).join('/')]}
        defaultOpenKeys={LeftNavMap.map(group => group.id)}
      >
        {renderSubMenus}
        {commonStore.user === null && (
          <Menu.Item key="loading">
            <Spin />
          </Menu.Item>
        )}
      </Menu>
    </LeftNavStyled>
  );
}
export default withRouter(observer(LeftNav));
