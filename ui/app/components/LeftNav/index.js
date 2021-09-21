import React from 'react';
import { Layout, Menu } from 'antd';
import { useLocation, withRouter } from 'react-router-dom';
import { Link } from 'helpers/Link';
import { default as Icon } from 'ui/components/IconAntd';
import pages from 'ui/pages';
import { APP_URL } from 'ui/config';
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
  const renderSubMenus = () => subMenus.map(group => <SubMenu
    key={group}
    title={
      <React.Fragment>
        <Icon component={LeftNavMap[group].icon} />
        {LeftNavMap[group].title}
      </React.Fragment>
    }
  >
    {getGroupPages(LeftNavMap[group]).map(page => <Menu.Item key={`/stamus/${pages[page].metadata.url || page.toLowerCase()}`}>
      <Link to={`${APP_URL}/${pages[page].metadata.url || CamelCaseToDashCase(page)}`}>{CamelCaseToNormal(page)}</Link>
    </Menu.Item>
    )}
  </SubMenu>
  )

  return (
    <Sider width={200} style={{ background: '#fff' }}>
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
