import React, { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useInjectSaga } from 'utils/injectSaga';
import { useInjectReducer } from 'utils/injectReducer';
import { dashboard } from 'ui/config/Dashboard';
import dashboardSelectors from 'ui/stores/dashboard/selectors';
import dashboardActions from 'ui/stores/dashboard/actions';
import dashboardReducer from 'ui/stores/dashboard/reducer';
import dashboardSaga from 'ui/stores/dashboard/saga';
import DashboardPanel from 'ui/components/DashboardPanel';
import DashboardBlockMore from 'ui/components/DashboardBlockMore';
import useKeyPress from 'ui/hooks/useKeyPress';
import selectors from 'ui/containers/App/selectors';
import { makeSelectGlobalFilters } from 'ui/containers/HuntApp/stores/global';
import { buildQFilter } from 'ui/buildQFilter';
import { createGlobalStyle } from 'styled-components';

const GlobalStyle = createGlobalStyle`
  .item-enter {
    transform: scaleY(0);
  }
  .item-enter-active {
    transition: all .5s ease-in;
    transform-origin: left top;
    transform: scaleY(1);
  }
  .item-exit {
    transform: scaleY(1);
    position: absolute;
  }
  .item-exit-active {
    transition: all .5s ease-out;
    transform-origin: left top;
    transform: scaleY(0);
    height: 0%;
  }
`;

const DashboardMosaic = () => {
  useInjectReducer({ key: 'dashboard', reducer: dashboardReducer });
  useInjectSaga({ key: 'dashboard', saga: dashboardSaga });
  const dispatch = useDispatch();
  const ctrl = useKeyPress('Control');
  const reload = useSelector(selectors.makeSelectGlobalFiltersDependency);
  const systemSettings = useSelector(selectors.makeSelectSystemSettings());
  const filtersWithAlert = useSelector(makeSelectGlobalFilters(true));
  const qfilter = buildQFilter(filtersWithAlert, systemSettings);

  useEffect(() => {
    Object.keys(dashboard).forEach(panelId => {
      dispatch(dashboardActions.getDashboardPanelRequest(panelId));
    });
  }, [reload, qfilter, JSON.stringify(filtersWithAlert)]);

  useEffect(() => {
    dispatch(dashboardActions.setEditMode(ctrl));
  }, [ctrl]);

  const panels = useSelector(dashboardSelectors.makeSelectDashboardPanels());
  const { visible, panelId, blockId } = useSelector(dashboardSelectors.makeSelectMoreResults());

  return (
    <div data-test="dashboard-mosaic">
      <GlobalStyle />
      {Object.keys(panels).map(panelId => (
        <DashboardPanel panelId={panelId} blocks={panels[panelId].data} loading={panels[panelId].loading} status={panels[panelId].status} />
      ))}
      <DashboardBlockMore
        visible={visible}
        panelId={panelId}
        blockId={blockId}
        onClose={() => dispatch(dashboardActions.setModalMoreResults(false))}
      />
    </div>
  );
};

export default DashboardMosaic;
