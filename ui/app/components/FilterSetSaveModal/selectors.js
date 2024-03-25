import { createSelector } from 'reselect';

import { initialState } from './reducer';

const selectForm = state => state.filterSetSave || initialState;
const makeSelectForm = () => createSelector(selectForm, subState => subState.request);

export default {
  makeSelectForm,
};
