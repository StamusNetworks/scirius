import React, { useCallback, useMemo } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Menu, Spin } from 'antd';
import { useLocation, withRouter } from 'react-router-dom';
import { default as Icon } from 'ui/components/IconAntd';
import pages from 'ui/pages';
import { APP_URL } from 'ui/config';
import { CamelCaseToNormal } from 'ui/helpers';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import { Link } from 'ui/helpers/Link';
import selectors from 'ui/containers/App/selectors';
import { createStructuredSelector } from 'reselect';
import { LinkOutlined } from '@ant-design/icons';
import { observer } from 'mobx-react-lite';
import { toJS } from 'mobx';
import { useStore } from 'ui/mobx/RootStoreProvider';
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

function LeftNav({ user }) {
  const {
    data: { permissions = [] },
    request: { loading = true },
  } = user;
  const { commonStore } = useStore();

  const renderMenuItems = useCallback(
    groupId =>
      getGroupPages(groupId, permissions, toJS(commonStore.systemSettings)).map(page => {
        const title = pages[page].metadata.title || CamelCaseToNormal(page);
        return (
          <Menu.Item key={`${APP_URL}/${pages[page].metadata.url}`} data-test="left-nav-menu-link-item">
            {typeof pages[page].metadata.url === 'function' ? (
              <LeftNavLink href={pages[page].metadata.url(toJS(commonStore.systemSettings))} target="_blank" className="left-nav-link">
                <div>{title}</div>
                <LinkOutlined />
              </LeftNavLink>
            ) : (
              <Link to={`${APP_URL}/${pages[page].metadata.url}`}>{title}</Link>
            )}
          </Menu.Item>
        );
      }),
    [toJS(commonStore.systemSettings), permissions],
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
    [toJS(commonStore.systemSettings), permissions],
  );

  return (
    <LeftNavStyled width={200}>
      <Menu
        mode="inline"
        selectedKeys={[useLocation().pathname.split('/').slice(0, 4).join('/')]}
        defaultOpenKeys={LeftNavMap.map(group => group.id)}
      >
        {renderSubMenus}
        {loading && (
          <Menu.Item key="loading">
            <Spin />
          </Menu.Item>
        )}
      </Menu>
    </LeftNavStyled>
  );
}

LeftNav.propTypes = {
  user: PropTypes.shape({
    data: PropTypes.object,
    request: PropTypes.object,
  }).isRequired,
};

const mapStateToProps = createStructuredSelector({
  user: selectors.makeSelectUser(),
});

export default connect(mapStateToProps)(withRouter(observer(LeftNav)));
