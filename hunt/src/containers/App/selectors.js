import { createSelector } from 'reselect';

const selectGlobal = (state) => state.get('global');

const selectRouter = (state) => state.get('router');

const makeSelectPlaceholder = () => createSelector(selectGlobal, (globalState) => globalState.get('placeholder'));

const makeSelectLocation = () => createSelector(selectRouter, (routerState) => routerState.get('location').toJS());

export {
    selectGlobal,
    makeSelectPlaceholder,
    makeSelectLocation,
};
