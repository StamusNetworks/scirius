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

function LeftNav({ user, systemSettings, hasLicense }) {
  const {
    data: { permissions = [] },
    request: { loading = true },
  } = user;

  const renderMenuItems = useCallback(
    groupId =>
      getGroupPages(groupId, permissions, systemSettings).map(page => {
        const title = pages[page].metadata.title || CamelCaseToNormal(page);
        return (
          <Menu.Item key={`${APP_URL}/${pages[page].metadata.url}`} data-test="left-nav-menu-link-item">
            {typeof pages[page].metadata.url === 'function' ? (
              <LeftNavLink href={pages[page].metadata.url(systemSettings)} target="_blank" className="left-nav-link">
                <div>{title}</div>
                <LinkOutlined />
              </LeftNavLink>
            ) : (
              <Link to={`${APP_URL}/${pages[page].metadata.url}`}>{title}</Link>
            )}
          </Menu.Item>
        );
      }),
    [systemSettings, permissions],
  );

  const renderSubMenus = useMemo(
    () =>
      LeftNavMap.map(group => {
        if (!hasLicense('nta') && group.nta) return null;
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
    [systemSettings, permissions],
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
  systemSettings: PropTypes.object,
  hasLicense: PropTypes.func.isRequired,
};

const mapStateToProps = createStructuredSelector({
  systemSettings: selectors.makeSelectSystemSettings(),
  user: selectors.makeSelectUser(),
  hasLicense: selectors.makeSelectHasLicense(),
});

export default connect(mapStateToProps)(withRouter(LeftNav));
