import produce from 'immer';
// CONSTANTS
import { createSelector } from 'reselect';

import { sections } from 'ui/constants';

export const ADD_FILTER = 'Hunt/HuntApp/ADD_FILTER';
export const REMOVE_FILTER = 'Hunt/HuntApp/REMOVE_FILTER';
export const EDIT_FILTER = 'Hunt/HuntApp/EDIT_FILTER';
export const CLEAR_FILTERS = 'Hunt/HuntApp/CLEAR_FILTERS';
export const SET_ALERT = 'Hunt/HuntApp/SET_ALERT';

export const validateFilter = filter => {
  if (filter.id === 'alert.tag') {
    // eslint-disable-next-line no-console
    console.error('Tags must go in a separate store');
    return false;
  }

  const filterProps = ['id', 'value', 'negated', 'label', 'fullString', 'query'];

  const filterKeys = Object.keys(filter);
  for (let i = 0; i < filterKeys.length; i += 1) {
    if (!filterProps.find(filterProp => filterProp === filterProps[i])) {
      return false;
    }
  }
  return true;
};

export const generateAlert = (informational = true, relevant = true, untagged = true, alerts = true, sightings = true) => ({
  id: 'alert.tag',
  value: { informational, relevant, untagged, alerts, sightings },
});

export const generateDefaultRequest = () => ({
  request: {
    loading: false,
    status: null,
    message: '',
  },
});

export const loadStorage = filtersType => {
  const initialFilterSet = undefined;
  let result;
  try {
    const cached = JSON.parse(localStorage.getItem(filtersType));
    result = typeof cached === 'undefined' ? initialFilterSet : cached;
  } catch (e) {
    result = initialFilterSet;
  }
  return result;
};

export function addFilter(filterType, filter) {
  return {
    type: ADD_FILTER,
    filterType,
    filter,
  };
}
export function removeFilter(filterType, filter) {
  return {
    type: REMOVE_FILTER,
    filterType,
    filter,
  };
}
export function editFilter(filterType, filter, filterUpdated) {
  return {
    type: EDIT_FILTER,
    filterType,
    filter,
    filterUpdated,
  };
}
export function clearFilters(filterType) {
  return {
    type: CLEAR_FILTERS,
    filterType,
  };
}
export function setTag(tagType) {
  return {
    type: SET_ALERT,
    tagType,
  };
}

// REDUCER
const initialState = {
  filters: {
    [sections.GLOBAL]: loadStorage(sections.GLOBAL) || [],
    [sections.HISTORY]: loadStorage(sections.HISTORY) || [],
    [sections.ALERT]: loadStorage(sections.ALERT) || generateAlert(),
  },
  [sections.USER]: {
    data: loadStorage(sections.USER) || {},
    ...generateDefaultRequest(),
  },
};

function indexOfFilter(filter, allFilters) {
  for (let idx = 0; idx < allFilters.length; idx += 1) {
    if (
      allFilters[idx].label === filter.label &&
      allFilters[idx].id === filter.id &&
      allFilters[idx].value === filter.value &&
      allFilters[idx].negated === filter.negated &&
      allFilters[idx].query === filter.query &&
      allFilters[idx].fullString === filter.fullString
    ) {
      return idx;
    }
  }
  return -1;
}

/* eslint-disable default-case */
export const reducer = (state = initialState, action) =>
  // eslint-disable-next-line consistent-return
  produce(state, draft => {
    switch (action.type) {
      case ADD_FILTER: {
        const { filter } = action;
        const globalFilters = draft.filters[action.filterType];
        // When an array of filters is passed
        if (Array.isArray(filter)) {
          for (let i = 0; i < filter.length; i += 1) {
            if (validateFilter(filter[i])) {
              globalFilters.push(filter[i]);
            }
          }
          // When a single filter is passed
        } else if (validateFilter(filter)) {
          globalFilters.push(filter);
        }
        draft.filters[action.filterType] = globalFilters;
        break;
      }
      case EDIT_FILTER: {
        if (!validateFilter(action.filterUpdated)) {
          return draft;
        }
        const globalFilters = draft.filters[action.filterType];
        const idx = indexOfFilter(action.filter, globalFilters);

        /* eslint-disable-next-line */
        const updatedGlobalFilters = globalFilters.map((filter, i) =>
          i === idx
            ? {
                ...filter,
                ...action.filterUpdated,
              }
            : filter,
        );

        draft.filters[action.filterType] = updatedGlobalFilters;
        break;
      }
      case REMOVE_FILTER: {
        const globalFilters = draft.filters[action.filterType];

        const idx = indexOfFilter(action.filter, globalFilters);
        const before = globalFilters.slice(0, idx);
        const after = globalFilters.slice(idx + 1);

        const updatedGlobalFilters = [...before, ...after];
        draft.filters[action.filterType] = updatedGlobalFilters;
        break;
      }
      case CLEAR_FILTERS: {
        draft.filters[action.filterType] = [];
        break;
      }
      case SET_ALERT: {
        // If an entire object is passed
        if (typeof action.tagType === 'object' && action.tagType !== null) {
          draft.filters[sections.ALERT] = action.tagType;
          // Or a single alert tag value
        } else {
          draft.filters[sections.ALERT].value[action.tagType] = !draft.filters[sections.ALERT].value[action.tagType];
        }
        break;
      }
    }
  });

// SELECTORS
export const selectGlobal = state => state.hunt;
export const makeSelectGlobalFilters = (includeAlertTag = false) =>
  createSelector(selectGlobal, globalState => {
    let result = globalState.filters[sections.GLOBAL];
    if (includeAlertTag) {
      result = [...result, globalState.filters[sections.ALERT]];
    }
    return result;
  });
export const makeSelectHistoryFilters = () => createSelector(selectGlobal, globalState => globalState.filters[sections.HISTORY]);
export const makeSelectAlertTag = () => createSelector(selectGlobal, globalState => globalState.filters[sections.ALERT]);

export const makeSelectUserRequest = () => createSelector(selectGlobal, globalState => globalState.user.request);
