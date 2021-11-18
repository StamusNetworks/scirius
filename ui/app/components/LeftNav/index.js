import React from 'react';
import { Layout, Menu } from 'antd';
import { useLocation, withRouter } from 'react-router-dom';
import { default as Icon } from 'ui/components/IconAntd';
import pages from 'ui/pages';
import { APP_URL, HUNT_URL } from 'ui/config';
import { CamelCaseToDashCase, CamelCaseToNormal } from 'ui/helpers';
import './style.scss';
import { LeftNavMap } from 'ui/maps/LeftNavMap';
import { Link } from 'ui/helpers/Link';

const { SubMenu } = Menu;
const { Sider } = Layout;

const pagesList = Object.keys(pages);
const subMenus = Object.keys(LeftNavMap);

const getGroupPages = (category) => pagesList
  .filter(page => pages[page].metadata && pages[page].metadata.category === category)
  .sort((a, b) => a - b)

function LeftNav() {
  const renderMenuItems = (group) => {
    if (group === 'HUNTING') return <Menu.Item key={`${HUNT_URL}`}>
      <a href={`${HUNT_URL}`}>Enriched Hunting</a>
    </Menu.Item>

    if (group === 'MANAGEMENT') return <Menu.Item key='/rules'>
      <a href='/rules'>Manager</a>
    </Menu.Item>

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
        defaultSelectedKeys={[useLocation().pathname]}
        defaultOpenKeys={subMenus}
        className="left-nav"
      >
        {renderSubMenus()}
      </Menu>
    </Sider>
  );
}

export default withRouter(LeftNav);
