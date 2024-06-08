/*
 *
 * LanguageProvider reducer
 *
 */
import produce from 'immer';

import { DEFAULT_LOCALE } from '../../i18n';
import { CHANGE_LOCALE } from './constants';

export const initialState = {
  locale: DEFAULT_LOCALE,
};

/* eslint-disable default-case */
const languageProviderReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case CHANGE_LOCALE:
        draft.locale = action.locale;
        break;
    }
  });

export default languageProviderReducer;
