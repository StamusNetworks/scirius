import React, { useState, useCallback, useMemo } from 'react';
import { observer } from 'mobx-react-lite';
import { Switch, Row, Empty } from 'antd';
import styled, { createGlobalStyle } from 'styled-components';

import { dashboard } from 'ui/config/Dashboard';
import DashboardPanel from 'ui/components/DashboardPanel';
import useKeyPress from 'ui/hooks/useKeyPress';
import DashboardContext from 'ui/context/DashboardContext';
import { useStore } from 'ui/mobx/RootStoreProvider';
import UISwitchLabel from 'ui/components/UIElements/UISwitchLabel';
import UICard from 'ui/components/UIElements/UICard';

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

const Card = styled(UICard)`
  margin-top: 0.5rem;
`;

const DashboardMosaic = () => {
  const { commonStore } = useStore();
  const ctrl = useKeyPress('Control');

  const isVisible = ({ panelId }) => {
    const callbacks = {
      discovery: () => commonStore.eventTypes.discovery,
      stamus: () => commonStore.eventTypes.stamus,
    };
    return callbacks[panelId] ? callbacks[panelId]() : true;
  };

  const localHideEmptyTiles = JSON.parse(localStorage.getItem('hide-empty-tiles'));

  const [hideEmptyTiles, setHideEmptyTiles] = useState(localHideEmptyTiles ?? true);

  const updateHideEmptyTiles = useCallback(hideEmptyTilesState => {
    setHideEmptyTiles(hideEmptyTilesState);
    localStorage.setItem('hide-empty-tiles', hideEmptyTilesState);
  }, []);

  const [emptyPanelsList, setEmptyPanelsList] = useState([]);
  const setPanelIsEmpty = useCallback(
    (panelId, isEmpty) => setEmptyPanelsList(prev => (isEmpty ? [...prev, panelId] : prev.filter(id => id !== panelId))),
    [setEmptyPanelsList],
  );
  const dashboardIsEmpty = useMemo(
    () => dashboard.filter(isVisible).every(panel => emptyPanelsList.includes(panel.panelId)),
    [
      emptyPanelsList,
      dashboard
        .filter(isVisible)
        .map(panel => panel.panelId)
        .join(' '),
    ],
  );

  return (
    <div data-test="dashboard-mosaic">
      <GlobalStyle />
      <Row justify="end" align="middle">
        <Switch
          data-test="hide-empty-tiles-switch"
          size="small"
          checkedChildren="ON"
          unCheckedChildren="OFF"
          checked={hideEmptyTiles}
          onChange={() => updateHideEmptyTiles(!hideEmptyTiles)}
        />{' '}
        <UISwitchLabel style={{ marginLeft: '4px' }}>Hide empty tiles</UISwitchLabel>
      </Row>

      <DashboardContext.Provider value={ctrl}>
        {dashboard.filter(isVisible).map(panel => (
          <DashboardPanel panel={panel} hideEmptyTiles={hideEmptyTiles} setPanelIsEmpty={setPanelIsEmpty} />
        ))}
        {hideEmptyTiles && dashboardIsEmpty && (
          <Card>
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No matching data found for the applied filters." />
          </Card>
        )}
      </DashboardContext.Provider>
    </div>
  );
};

export default observer(DashboardMosaic);
