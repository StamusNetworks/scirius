import React from 'react';
import { Layout, Menu } from 'antd';
import { useHistory, useLocation, withRouter } from 'react-router-dom';
import { default as Icon } from 'ui/components/IconAntd';
import pages from 'ui/pages';
import { APP_URL, HUNT_URL } from 'ui/config';
import { CamelCaseToDashCase, CamelCaseToNormal } from 'ui/helpers';
import './style.scss';
import { LeftNavMap } from 'ui/maps/LeftNavMap';

const { SubMenu } = Menu;
const { Sider } = Layout;

const pagesList = Object.keys(pages);

const subMenus = Object.keys(LeftNavMap);

const getGroupPages = (category) => pagesList
  .filter(page => pages[page].metadata && pages[page].metadata.category === category)
  .sort((a, b) => a - b)

function LeftNav() {
  const history = useHistory();

  const renderMenuItems = (group) => {
    if (group === 'HUNTING') return <Menu.Item
      onClick={() => history.push(`${HUNT_URL}`)}
      key={`${HUNT_URL}`}
    >
      Enriched Hunting
    </Menu.Item>

    if (group === 'MANAGEMENT') return <Menu.Item
      onClick={() => history.push('/rules')}
      key={group}
    >
      Manager
    </Menu.Item>

    return getGroupPages(LeftNavMap[group]).map(page =>
      <Menu.Item
        onClick={() => history.push(`${APP_URL}/${pages[page].metadata.url || CamelCaseToDashCase(page)}`)}
        key={`/stamus/${pages[page].metadata.url || page.toLowerCase()}`}
      >
        {CamelCaseToNormal(page)}
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
