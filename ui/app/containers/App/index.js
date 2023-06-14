/**
 *
 * App
 *
 * This component is the skeleton around the actual pages, and should only
 * contain code that should be seen on all pages. (e.g. navigation bar)
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Switch, Redirect, Route } from 'react-router-dom';
import PropTypes from 'prop-types';
import { bindActionCreators, compose } from 'redux';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { Layout } from 'antd';
import { observer } from 'mobx-react-lite';

import withSaga from 'utils/injectSaga';
import pages from 'ui/pages';
import { APP_URL } from 'ui/config';
import { CamelCaseToDashCase } from 'ui/helpers';
import { Content } from 'ui/components';
import Header from 'ui/components/Header';
import LeftNav from 'ui/components/LeftNav';
import GlobalStyle from 'ui/global-styles';
import actions from 'ui/containers/App/actions';
import selectors from 'ui/containers/App/selectors';
import ErrorHandler from 'ui/components/ErrorHandler';
import ProxyRoute from 'ui/components/ProxyRoute';
import saga from 'ui/containers/App/saga';
import FilterSets from 'ui/components/FilterSets';
import AppSpinner from 'ui/components/AppSpinner';
import useAutorun from 'ui/helpers/useAutorun';
import { useStore } from 'ui/mobx/RootStoreProvider';

const pagesList = Object.keys(pages);
const SESSION_INTERVAL = 30000;

const App = ({ source, getSystemSettings, getUser, getSource, getAllPeriodRequest, setSessionActivity, timeSpan }) => {
  const idle = useRef(0);

  const setIdle = useCallback(() => {
    idle.current = 0;
  }, [idle]);

  const { commonStore } = useStore();

  useAutorun(async () => {
    await commonStore.fetchSystemSettings();
    await commonStore.fetchSources();
  }, []);

  useEffect(() => {
    if (source.data.length === 0) {
      getSource();
    }
    getSystemSettings();
    getUser();
    getAllPeriodRequest();

    let interval = null;
    if (process.env.NODE_ENV === 'production') {
      interval = setInterval(() => {
        idle.current += SESSION_INTERVAL;
        setSessionActivity(idle.current / 1000);
      }, SESSION_INTERVAL);
      document.addEventListener('mousemove', setIdle);
      document.addEventListener('keypress', setIdle);
    }
    return () => {
      if (process.env.NODE_ENV === 'production') {
        clearInterval(interval);
        document.removeEventListener('mousemove', setIdle);
        document.removeEventListener('keypress', setIdle);
      }
    };
  }, []);

  useEffect(() => {
    getAllPeriodRequest();
  }, [timeSpan.now]);

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

  // do not render the app if systemSettings are not yet fetched
  if (!commonStore.systemSettings) {
    return <AppSpinner />;
  }

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
              {pagesList
                .filter(page => typeof pages[page].metadata.url !== 'function')
                .map(page => {
                  if (!commonStore.systemSettings.license?.nta && pages[page].metadata.nta) return null;
                  return (
                    <Route key={page} exact path={`${APP_URL}/${pages[page].metadata.url || CamelCaseToDashCase(page)}`} component={pages[page]} />
                  );
                })
                .filter(route => route)}
              <Route exact path={['/', APP_URL]}>
                {pages.OperationalCenter ? (
                  <Redirect to={`${APP_URL}/security-posture/operational-center`} />
                ) : (
                  <Redirect to={`${APP_URL}/hunting/dashboards`} />
                )}
              </Route>
              <ProxyRoute />
            </Switch>
            <FilterSets />
          </Content>
        </ErrorHandler>
      </Layout>
    </Layout>
  );
};

App.propTypes = {
  source: PropTypes.object,
  getSystemSettings: PropTypes.func,
  getUser: PropTypes.func,
  getSource: PropTypes.any,
  getAllPeriodRequest: PropTypes.any,
  setSessionActivity: PropTypes.func,
  timeSpan: PropTypes.object,
};

const mapStateToProps = createStructuredSelector({
  source: selectors.makeSelectSource(),
  timeSpan: selectors.makeSelectTimespan(),
});

export const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      getSystemSettings: actions.getSystemSettingsRequest,
      getUser: actions.getUser,
      getSource: actions.getSource,
      getAllPeriodRequest: actions.getAllPeriodRequest,
      setSessionActivity: actions.setSessionActivityRequest,
    },
    dispatch,
  );

const withConnect = connect(mapStateToProps, mapDispatchToProps);
export default withSaga({ key: 'root', saga })(compose(withConnect)(observer(App)));
