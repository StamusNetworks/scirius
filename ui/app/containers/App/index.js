/**
 *
 * App
 *
 * This component is the skeleton around the actual pages, and should only
 * contain code that should be seen on all pages. (e.g. navigation bar)
 */
import React, { useEffect, useState } from 'react';
import { Switch, Redirect, Route } from 'react-router-dom';
import { Layout } from 'antd';
import pages from 'ui/pages';
import { APP_URL } from 'ui/config';
import './style.scss'; // please dont move it! should be loaded before all components
import { CamelCaseToDashCase } from 'ui/helpers';
import { Content } from 'ui/components';
import Header from 'ui/components/Header';
import LeftNav from 'ui/components/LeftNav';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { syncUrl } from 'ui/helpers/syncUrl';

import { bindActionCreators, compose } from 'redux';
import PropTypes from 'prop-types';
import './commonKillChainStyles.scss';
import GlobalStyle from 'ui/global-styles';
import actions from 'ui/containers/App/actions';
import selectors from 'ui/containers/App/selectors';
import ErrorHandler from 'ui/components/ErrorHandler';

const pagesList = Object.keys(pages);

const App = ({
  source,
  getGlobalSettings,
  getUser,
  getSource,
}) => {
  useEffect(() => {
    if (source.data.length === 0) {
      getSource();
    }
    getGlobalSettings();
    syncUrl();
    getUser();
  }, []);

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

  return (
    <Layout>
      {errorMsg && <pre id="rf_js_error">{errorMsg}</pre>}
      <GlobalStyle />
      <ErrorHandler>
        <Header />
      </ErrorHandler>
      <Layout>
        <ErrorHandler>
          <LeftNav />
        </ErrorHandler>
        <ErrorHandler>
          <Content>
            <Switch>
              {pagesList.map(page => <Route key={page} exact path={`${APP_URL}/${pages[page].metadata.url || CamelCaseToDashCase(page)}`} component={pages[page]} />)}
              <Route exact path={["/", APP_URL]}>
                {pages.Overview ? <Redirect to={`${APP_URL}/security-posture/overview`} /> : <Redirect to={`${APP_URL}/explorer`} />}
              </Route>
              <Route path="" component={pages.NotFoundPage} />
            </Switch>
          </Content>
        </ErrorHandler>
      </Layout>
    </Layout>
  );
}

App.propTypes = {
  source: PropTypes.object,
  getGlobalSettings: PropTypes.any,
  getUser: PropTypes.func,
  getSource: PropTypes.any,
};

const mapStateToProps = createStructuredSelector({
  startDate: selectors.makeSelectStartDate(),
  endDate: selectors.makeSelectEndDate(),
  reloadData: selectors.makeSelectReload(),
  globalSettings: selectors.makeSelectGlobalSettings(),
  filtersParam: selectors.makeSelectFiltersParam(),
  source: selectors.makeSelectSource(),
});

export const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      getGlobalSettings: actions.getGlobalSettings,
      getUser: actions.getUser,
      getSource: actions.getSource,
    },
    dispatch,
  );

const withConnect = connect(
  mapStateToProps,
  mapDispatchToProps,
);
export default compose(withConnect)(App);
