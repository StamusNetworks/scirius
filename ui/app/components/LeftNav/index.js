import React, { Fragment, useState, useEffect } from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import { Layout, Menu, Spin } from 'antd';
import { LoadingOutlined } from '@ant-design/icons';
import { useLocation, withRouter } from 'react-router-dom';
import { default as Icon } from 'ui/components/IconAntd';
import pages from 'ui/pages';
import { APP_URL, HUNT_URL } from 'ui/config';
import { CamelCaseToDashCase, CamelCaseToNormal } from 'ui/helpers';
import './style.scss';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import { Link } from 'ui/helpers/Link';
import * as config from 'ui/config';
import request from 'utils/request';

const { SubMenu } = Menu;
const { Sider } = Layout;

const pagesList = Object.keys(pages);
const subMenus = Object.keys(LeftNavMap);

const getGroupPages = (category) => pagesList
  .filter(page => pages[page].metadata && pages[page].metadata.category === category)
  .sort((a, b) => a - b)

function LeftNav({ user }) {
  const {
    data: { permissions = [] },
    request: { loading },
  } = user;
  const [systemSettings, setSystemSettings] = useState({});

  useEffect(() => {
    (async () => setSystemSettings(await request(config.SYSTEM_SETTINGS_PATH)))();
  }, []);

  const renderMenuItems = (group) => {
    if (group === 'STAMUS_ND') return (<Fragment>
      <Menu.Item key={`${HUNT_URL}`}>
        <a href={`${HUNT_URL}`}>Enriched Hunting</a>
      </Menu.Item>
      <Menu.Item key='/rules'>
        <a href='/rules'>Manager</a>
      </Menu.Item>
    </Fragment>)

    if (group === 'OTHER_APPS') return (<Fragment>
      {systemSettings.kibana && permissions.includes('rules.events_kibana') && (
        <Menu.Item key='kibana'>
          <a href={systemSettings.kibana_url} target="_blank">Kibana</a>
        </Menu.Item>
      )}
      {systemSettings.evebox && permissions.includes('rules.events_evebox') && (
        <Menu.Item key='evebox'>
          <a href={systemSettings.evebox_url} target="_blank">EveBox</a>
        </Menu.Item>
      )}
      {systemSettings.cyberchef && (
        <Menu.Item key='cyberchef'>
          <a href={systemSettings.cyberchef_url} target="_blank">CyberChef</a>
        </Menu.Item>
      )}
      {loading && <Menu.Item key='loading'><Spin indicator={<LoadingOutlined spin />} /></Menu.Item>}
    </Fragment>)

    return getGroupPages(LeftNavMap[group]).map(page =>
      <Menu.Item
        key={`/stamus/${pages[page].metadata.url || page.toLowerCase()}`}
      >
        <Link to={`${APP_URL}/${pages[page].metadata.url || CamelCaseToDashCase(page)}`}>
          {CamelCaseToNormal(page)}
        </Link>
      </Menu.Item>
    )
  }

  const renderSubMenus = () => subMenus.map(group => <SubMenu
    key={group}
    title={
      <React.Fragment>
        <Icon component={LeftNavMap[group].icon} />
        {LeftNavMap[group].title}
      </React.Fragment>
    }
  >
    {renderMenuItems(group)}
  </SubMenu>
  )

  return (
    <Sider width={200} style={{ background: '#fff', minHeight: "calc(100vh - 64px)" }}>
      <Menu
        mode="inline"
        selectedKeys={[useLocation().pathname]}
        defaultOpenKeys={subMenus}
        className="left-nav"
      >
        {renderSubMenus()}
      </Menu>
    </Sider>
  );
}

LeftNav.propTypes = {
  user: PropTypes.shape({
    data: PropTypes.object,
    request: PropTypes.object,
  }).isRequired,
};

const mapStateToProps = ({global}) => ({user: global.ce ? global.ce.user : global.user})

export default connect(
  mapStateToProps
)(withRouter(LeftNav));
