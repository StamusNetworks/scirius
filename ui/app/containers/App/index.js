/**
 *
 * App
 *
 * This component is the skeleton around the actual pages, and should only
 * contain code that should be seen on all pages. (e.g. navigation bar)
 */
import React, { useEffect, useRef, useState } from 'react';
import { Switch, Route, Link } from 'react-router-dom';
import { Layout, notification } from 'antd';
import pages from 'ui/pages';
import './style.scss'; // please dont move it! should be loaded before all components
import { CamelCaseToDashCase, CamelCaseToNormal } from 'ui/helpers';
import { Sider, Content, LinkGroup, LinkGroupTitle, SideLink } from 'ui/components';
import Header from 'ui/components/Header';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { syncUrl } from 'ui/helpers/syncUrl';

import { bindActionCreators, compose } from 'redux';
import PropTypes from 'prop-types';
import { first } from 'lodash';
import { useHttpNotifications } from 'ui/hooks/useHttpNotifications';
import { usePrevious } from 'ui/hooks/usePrevious';
import history from 'utils/history';
import './commonKillChainStyles.scss';
import GlobalStyle from 'ui/global-styles';
import {
  getActiveFamilies,
  getActiveThreats,
  getFamilies,
  getGlobalSettings, getSource,
  getThreats,
  getUser, setDuration, setTimeSpan,
} from './actions';
import {
  makeSelectEndDate,
  makeSelectFamilies,
  makeSelectFiltersParam,
  makeSelectGlobalSettings,
  makeSelectReload,
  makeSelectSource,
  makeSelectStartDate,
  makeSelectThreats,
  makeSelectUser,
} from './selectors';

const pagesList = Object.keys(pages);

const getGroups = () => pagesList
    .map(page => pages[page].metadata && pages[page].metadata.category)
    .filter((page, index, self) => self.indexOf(page) === index && page !== undefined)

const getGroupPages = (category) => pagesList
    .filter(page => pages[page].metadata && pages[page].metadata.category === category)
    .sort((a, b) => a - b)

const App = ({
  families,
  user,
  threats,
  source,
  getGlobalSettings,
  getFamilies,
  getUser,
  getThreats,
  getActiveFamilies,
  getActiveThreats,
  getSource,
  startDate,
  endDate,
  reloadData,
  filtersParam,
}) => {
  const linkGroups = getGroups();

  const familyNotifications = useHttpNotifications({ request: families.list.request, notifyFailures: true });
  const threatNotifications = useHttpNotifications({ request: threats.active, notifyFailures: true });

  const noDataWarning = useRef(false);
  const prevFamiliesLoading = usePrevious(families.list.request.loading);

  useEffect(() => {
    getFamilies();
    getThreats();
  }, [filtersParam]);

  useEffect(() => {
    if (source.data.length === 0) {
      getSource();
    }
    getGlobalSettings();
    syncUrl();
    getUser();
  }, []);

  useEffect(() => {
    // dont make the request the first time when the length is 0!
    if (families.list.data.length > 0) getActiveFamilies();

    // re-fetch the families on route change
    history.listen(() => families.list.data.length > 0 && getActiveFamilies());

    for (let i = 0; i < families.list.data.length; i += 1) {
      setTimeout(() => {
        getActiveThreats(families.list.data[i].pk);
      }, 50 * i);
    }
  }, [families.list.data, startDate.unix(), endDate.unix(), filtersParam, reloadData.now]);

  const [errorMsg, setErrorMsg] = useState(null);

  useEffect(() => {
    if (window.localStorage.getItem('rf_debug_mode') === '1') {
      window.onerror = (msg, url, line, col, error) => {
        if (msg.indexOf('ResizeObserver loop limit exceeded') !== -1) {
          // This error is harmless and can be ignored, see:
          // https://stackoverflow.com/questions/49384120/resizeobserver-loop-limit-exceeded
          return false;
        }
        let extra = !col ? '' : `\ncolumn: ${col}`;
        extra += !error ? '' : `\nerror: ${error}`;
        const err = `JS Error: ${msg}\nurl: ${url}\nline: ${line}${extra}`;
        setErrorMsg(err);
        return false;
      };
    }
  });

  if (
    !noDataWarning.current &&
    families.list.data.length === 0 &&
    families.list.request.status &&
    prevFamiliesLoading &&
    !families.list.request.loading
  ) {
    noDataWarning.current = true;
    const firstSource = first(source.data) || {};
    const { version: sourceVersion = 0 } = firstSource;
    notification.warning({
      message: sourceVersion === 0 ? 'No data!' : 'Warning',
      description: (
        <React.Fragment>
          {sourceVersion > 0 && (
            <React.Fragment>
              No data for the selected filter/s. <br />
              Please try selecting another or removing it.
            </React.Fragment>
          )}
          {sourceVersion === 0 && (
            <React.Fragment>
              No Stamus Threat Intelligence data is available. Please{' '}
              <a href="/static/doc/ruleset.html#updating-source" target="_blank">
                update the sources
              </a>{' '}
              if Scirius Security platform is connected to Internet or{' '}
              <a href="/static/doc/str.html#offline" target="_blank">
                define and update Stamus Threat Intelligence source
              </a>{' '}
              if the SSP is offline or air gapped
            </React.Fragment>
          )}
        </React.Fragment>
      ),
      duration: sourceVersion === 0 ? 60 : 5,
      onClose: () => {
        noDataWarning.current = false;
      },
    });
  }

  return (
    <Layout>
      {errorMsg && <pre id="rf_js_error">{errorMsg}</pre>}
      <React.Fragment>{familyNotifications}</React.Fragment>
      <React.Fragment>{threatNotifications}</React.Fragment>
      <GlobalStyle />
      <Header />
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


App.propTypes = {
  families: PropTypes.object,
  user: PropTypes.object,
  threats: PropTypes.object,
  getFamilies: PropTypes.func,
  startDate: PropTypes.any,
  endDate: PropTypes.any,
  reloadData: PropTypes.object,
  source: PropTypes.object,
  getGlobalSettings: PropTypes.any,
  getUser: PropTypes.func,
  getThreats: PropTypes.any,
  getActiveFamilies: PropTypes.any,
  getActiveThreats: PropTypes.any,
  getSource: PropTypes.any,
  filtersParam: PropTypes.any,
};

const mapStateToProps = createStructuredSelector({
  families: makeSelectFamilies(),
  user: makeSelectUser(),
  threats: makeSelectThreats(),
  startDate: makeSelectStartDate(),
  endDate: makeSelectEndDate(),
  reloadData: makeSelectReload(),
  globalSettings: makeSelectGlobalSettings(),
  filtersParam: makeSelectFiltersParam(),
  source: makeSelectSource(),
});

export const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      getGlobalSettings,
      getFamilies,
      getActiveFamilies,
      getUser,
      getThreats,
      getActiveThreats,
      getSource,
    },
    dispatch,
  );

const withConnect = connect(
  mapStateToProps,
  mapDispatchToProps,
);
export default compose(withConnect)(App);
