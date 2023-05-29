import React, { createContext, useContext } from 'react';
import PropTypes from 'prop-types';
import { store } from 'ui/mobx/stores/RootStore';
// import { store } from './store';

// create the context
const StoreContext = createContext(null);

// create the provider component
export const RootStoreProvider = ({ children }) => {
  // only create the store once ( store is a singleton)
  // const root = store ?? new RootStore();

  return <StoreContext.Provider value={store}>{children}</StoreContext.Provider>;
};
RootStoreProvider.propTypes = {
  children: PropTypes.string,
};

// create the hook
export const useStore = () => {
  const context = useContext(StoreContext);
  if (context === undefined) {
    throw new Error('useRootStore must be used within RootStoreProvider');
  }

  return context;
};
