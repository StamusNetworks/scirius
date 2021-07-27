/**
 *
 * App
 *
 * This component is the skeleton around the actual pages, and should only
 * contain code that should be seen on all pages. (e.g. navigation bar)
 */
import React from 'react';
import { Switch, Route } from 'react-router-dom';
import { Layout } from 'antd';
import pages from 'ui/pages';
import { CamelCaseToDashCase, CamelCaseToNormal } from 'ui/helpers';
import { Header, Sider, Content, LinkGroup, LinkGroupTitle, SideLink } from 'ui/components';
import GlobalStyle from '../../global-styles';
const pagesList = Object.keys(pages);

const getGroups = () => pagesList
    .map(page => pages[page].metadata && pages[page].metadata.category)
    .filter((page, index, self) => self.indexOf(page) === index && page !== undefined)

const getGroupPages = (category) => pagesList
    .filter(page => pages[page].metadata && pages[page].metadata.category === category)
    .sort((a, b) => a - b)

function App() {
  const linkGroups = getGroups();
  return (
    <Layout>
      <GlobalStyle />
      <Header>
      </Header>
      <Layout>
        <Sider>
          {linkGroups.map(group => <LinkGroup key={group}>
            <LinkGroupTitle title={group} />
            {getGroupPages(group).map(page => <SideLink key={page} to={CamelCaseToDashCase(page)}>{CamelCaseToNormal(page)}</SideLink>)}
          </LinkGroup>)}
        </Sider>
        <Content>
          <Switch>
            {pagesList.map(page => (
              <Route key={page} exact path={`/${CamelCaseToDashCase(page)}`} component={pages[page]} />
            ))}
            <Route path="" component={pages.NotFoundPage} />
          </Switch>
        </Content>
      </Layout>
    </Layout>
  );
}

export default App;
