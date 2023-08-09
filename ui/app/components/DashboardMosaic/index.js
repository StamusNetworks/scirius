import React from 'react';
import { dashboard } from 'ui/config/Dashboard';
import DashboardPanel from 'ui/components/DashboardPanel';
import useKeyPress from 'ui/hooks/useKeyPress';
import { createGlobalStyle } from 'styled-components';
import DashboardContext from 'ui/context/DashboardContext';
import { observer } from 'mobx-react-lite';
import { useStore } from 'ui/mobx/RootStoreProvider';

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
  const { commonStore } = useStore();
  const ctrl = useKeyPress('Control');

  const isVisible = panelId => {
    const callbacks = {
      discovery: () => commonStore.eventTypes.discovery,
    };
    return callbacks[panelId] ? callbacks[panelId]() : true;
  };

  return (
    <div data-test="dashboard-mosaic">
      <GlobalStyle />
      <DashboardContext.Provider value={ctrl}>
        {Object.keys(dashboard)
          .filter(isVisible)
          .map(panelId => (
            <DashboardPanel panelId={panelId} />
          ))}
      </DashboardContext.Provider>
    </div>
  );
};

export default observer(DashboardMosaic);
