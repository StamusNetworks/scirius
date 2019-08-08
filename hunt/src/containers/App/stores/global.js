// CONSTANTS
import { fromJS } from 'immutable';
import { createSelector } from 'reselect';

export const ADD_FILTER = 'Hunt/App/ADD_FILTER';
export const REMOVE_FILTER = 'Hunt/App/REMOVE_FILTER';
export const EDIT_FILTER = 'Hunt/App/EDIT_FILTER';
export const CLEAR_FILTERS = 'Hunt/App/CLEAR_FILTERS';
export const SET_ALERT = 'Hunt/App/SET_ALERT';
export const SET_ONLY_ONE_ALERT = 'Hunt/App/SET_ONLY_ONE_ALERT';

export const sections = {
    GLOBAL: 'ids_filters',
    HISTORY: 'history_filters',
    ALERT: 'alert_tag',
};

export const validateFilter = (filter) => {
    const filterProps = ['id', 'value', 'negated', 'label', 'fullString', 'query'];

    const filterKeys = Object.keys(filter);
    for (let i = 0; i < filterKeys.length; i += 1) {
        if (!filterProps.find((filterProp) => filterProp === filterProps[i])) { return false }
    }
    return true;
}

const generateAlert = (informational = true, relevant = true, untagged = true) => ({
    id: 'alert.tag',
    value: { informational, relevant, untagged }
});

const updateStorage = (filterType, filters) => {
    localStorage.setItem(filterType, JSON.stringify(filters));
}

const loadStorage = (filtersType) => {
    const initialFilterSet = undefined;
    let result;
    try {
        const cached = JSON.parse(localStorage.getItem(filtersType));
        result = (typeof cached === 'undefined') ? initialFilterSet : cached;
    } catch (e) {
        result = initialFilterSet;
    }
    return result;
}

export function addFilter(filterType, filter) {
    return {
        type: ADD_FILTER,
        filterType,
        filter
    };
}
export function removeFilter(filterType, filterIdx) {
    return {
        type: REMOVE_FILTER,
        filterType,
        filterIdx
    };
}
export function editFilter(filterType, filterIdx, filterUpdated) {
    return {
        type: EDIT_FILTER,
        filterType,
        filterIdx,
        filterUpdated
    };
}
export function clearFilters(filterType) {
    return {
        type: CLEAR_FILTERS,
        filterType
    };
}
export function setTag(tagType, tagState) {
    return {
        type: SET_ALERT,
        tagType,
        tagState,
    }
}
export function enableOnly(filterType) {
    return {
        type: SET_ONLY_ONE_ALERT,
        filterType
    }
}

// REDUCER
const initialState = fromJS({
    filters: {
        [sections.GLOBAL]: loadStorage(sections.GLOBAL) || [],
        [sections.HISTORY]: loadStorage(sections.HISTORY) || [],
        [sections.ALERT]: loadStorage(sections.ALERT) || generateAlert(),
    },
});

export const reducer = (state = initialState, action) => {
    switch (action.type) {
        case ADD_FILTER: {
            const { filter } = action;
            const globalFilters = state.getIn(['filters', action.filterType]).toJS();
            // When an array of filters is passed
            if (Array.isArray(filter)) {
                for (let i = 0; i < filter.length; i += 1) {
                    if (validateFilter(filter[i])) {
                        globalFilters.push(filter[i]);
                    }
                }
            // When a single filter is passed
            } else {
                globalFilters.push(action.filter);
            }
            updateStorage(action.filterType, globalFilters);
            return state.setIn(['filters', action.filterType], fromJS(globalFilters));
        }
        case EDIT_FILTER: {
            if (!validateFilter(action.filterUpdated)) { return state }
            const globalFilters = state.getIn(['filters', action.filterType]).toJS();
            /* eslint-disable-next-line */
            const updatedGlobalFilters = globalFilters.map((filter, i) => (i === action.filterIdx) ? {
                ...filter,
                ...action.filterUpdated
            } : filter);
            updateStorage(updatedGlobalFilters);
            return state.setIn(['filters', action.filterType], fromJS(updatedGlobalFilters));
        }
        case REMOVE_FILTER: {
            const globalFilters = state.getIn(['filters', action.filterType]).toJS();
            const before = globalFilters.slice(0, action.filterIdx);
            const after = globalFilters.slice(action.filterIdx + 1);
            const updatedGlobalFilters = [...before, ...after];
            updateStorage(action.filterType, updatedGlobalFilters);
            return state.setIn(['filters', action.filterType], fromJS(updatedGlobalFilters));
        }
        case CLEAR_FILTERS: {
            updateStorage(action.filterType, []);
            return state.setIn(['filters', action.filterType], fromJS([]));
        }
        case SET_ALERT: {
            const updatedAlert = state.setIn(['filters', sections.ALERT, 'value', action.tagType], action.tagState);
            updateStorage(sections.ALERT, updatedAlert.getIn(['filters', sections.ALERT]).toJS());
            return updatedAlert;
        }
        case SET_ONLY_ONE_ALERT: {
            const { filterType } = action;
            const updatedAlert = state.setIn(['filters', sections.ALERT], fromJS(generateAlert(filterType === 'informational' || filterType === 'all', filterType === 'relevant' || filterType === 'all', filterType === 'untagged' || filterType === 'all')));
            updateStorage(sections.ALERT, updatedAlert.getIn(['filters', sections.ALERT]).toJS());
            return updatedAlert;
        }
        default:
            return state;
    }
}

// SELECTORS
export const selectGlobal = (state) => state.get('global');
export const makeSelectGlobalFilters = (includeAlertTag = false) => createSelector(selectGlobal, (globalState) => {
    let result = globalState.getIn(['filters', sections.GLOBAL]).toJS();
    if (includeAlertTag) {
        result = [...result, globalState.getIn(['filters', sections.ALERT]).toJS()];
    }
    return result;
});
export const makeSelectHistoryFilters = () => createSelector(selectGlobal, (globalState) => globalState.getIn(['filters', sections.HISTORY]).toJS());
export const makeSelectAlertTag = () => createSelector(selectGlobal, (globalState) => globalState.getIn(['filters', sections.ALERT]).toJS());
