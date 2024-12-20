/**
 *
 * App
 *
 * This component is the skeleton around the actual pages, and should only
 * contain code that should be seen on all pages. (e.g. navigation bar)
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';

import { ConfigProvider, Layout } from 'antd';
import { observer } from 'mobx-react-lite';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Switch, Redirect, Route } from 'react-router-dom';
import { bindActionCreators, compose } from 'redux';
import { createStructuredSelector } from 'reselect';

import AppSpinner from 'ui/components/AppSpinner';
import Content from 'ui/components/Content';
import ErrorHandler from 'ui/components/ErrorHandler';
import FilterSets from 'ui/components/FilterSets';
import Header from 'ui/components/Header';
import LeftNav from 'ui/components/LeftNav';
import ProxyRoute from 'ui/components/ProxyRoute';
import { APP_URL } from 'ui/config';
import { theme } from 'ui/config/theme';
import actions from 'ui/containers/App/actions';
import saga from 'ui/containers/App/saga';
import selectors from 'ui/containers/App/selectors';
import GlobalStyle from 'ui/global-styles';
import { CamelCaseToDashCase } from 'ui/helpers';
import notify from 'ui/helpers/notify';
import useAutorun from 'ui/helpers/useAutorun';
import { useStore } from 'ui/mobx/RootStoreProvider';
import pages from 'ui/pages';
import withSaga from 'utils/injectSaga';

const pagesList = Object.keys(pages);
const SESSION_INTERVAL = 30000;

const App = ({ setSessionActivity }) => {
  const idle = useRef(0);

  const setIdle = useCallback(() => {
    idle.current = 0;
  }, [idle]);

  const { commonStore } = useStore();

  useEffect(async () => {
    /* Do not reload the following endpoints since they don't use and listen to start/end times or other filters */
    await commonStore.fetchSystemSettings();
    await commonStore.fetchSources();
    await commonStore.fetchUser();
    await commonStore.fetchLinkTemplates();
  }, []);

  useEffect(() => {
    try {
      const localTimerange = JSON.parse(localStorage.getItem('str-timespan'));
      if (localTimerange.timePicker === 'relative') commonStore.setRelativeTimeRange(localTimerange.duration);
    } catch (e) {
      notify.error('Failed initializing relative time range');
    }
  }, []);

  useAutorun(async () => {
    await commonStore.fetchAllPeriod();
  }, ['tenant']);

  useEffect(() => {
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
    <ConfigProvider theme={theme}>
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
    </ConfigProvider>
  );
};

App.propTypes = {
  setSessionActivity: PropTypes.func,
};

const mapStateToProps = createStructuredSelector({
  timeSpan: selectors.makeSelectTimespan(),
});

export const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      setSessionActivity: actions.setSessionActivityRequest,
    },
    dispatch,
  );

const withConnect = connect(mapStateToProps, mapDispatchToProps);
export default withSaga({ key: 'root', saga })(compose(withConnect)(observer(App)));
