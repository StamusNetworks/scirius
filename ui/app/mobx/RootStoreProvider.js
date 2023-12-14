import React, { createContext, useContext } from 'react';
import PropTypes from 'prop-types';
import RootStore from 'ui/mobx/stores/RootStore';
// import { store } from './store';

// create the context
const StoreContext = createContext(null);

// create the provider component
// eslint-disable-next-line arrow-body-style

export const store = new RootStore();
export const RootStoreProvider = ({ children }) => {
  // only create the store once ( store is a singleton)
  const root = store ?? new RootStore();

  return <StoreContext.Provider value={root}>{children}</StoreContext.Provider>;
};
RootStoreProvider.propTypes = {
  children: PropTypes.object,
};

/* Hook to use store in any functional component */
export const useStore = () => {
  const store = useContext(StoreContext);
  if (store === undefined) {
    throw new Error('useRootStore must be used within RootStoreProvider');
  }

  return store;
};

/* HOC to inject store to any functional or class component */
export const withStore = Component => props => <Component {...props} store={useStore()} />;
