/*
 * AppReducer
 *
 * The reducer takes care of our data. Using actions, we can
 * update our application state. To add a new action,
 * add it to the switch statement in the reducer function
 *
 */

import produce from 'immer';
import store from 'store';
import moment from 'moment';
import history from 'utils/history';
import { isEqual } from 'lodash';

import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import { StorageEnum } from 'ui/maps/StorageEnum';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import { parseUrl } from 'ui/helpers/parseUrl';
import { getQueryObject } from 'ui/helpers/getQueryObject';
import { isBooted, setBooted } from 'ui/helpers/isBooted';
import {
  LOCATION_CHANGE,
  DO_RELOAD,
  GET_FAMILIES_REQUEST,
  GET_FAMILIES_FAILURE,
  GET_FAMILIES_SUCCESS,
  GET_USER_REQUEST,
  GET_USER_SUCCESS,
  GET_USER_FAILURE,
  GET_THREATS_FAILURE,
  GET_THREATS_REQUEST,
  GET_THREATS_SUCCESS,
  SET_DURATION,
  SET_RELOAD,
  SET_TIME_SPAN,
  GET_ACTIVE_THREATS_REQUEST,
  GET_ACTIVE_THREATS_SUCCESS,
  GET_ACTIVE_THREATS_FAILURE,
  GET_TENANTS_REQUEST,
  GET_TENANTS_SUCCESS,
  GET_TENANTS_FAILURE,
  GET_GLOBAL_SETTINGS_REQUEST,
  GET_GLOBAL_SETTINGS_SUCCESS,
  GET_GLOBAL_SETTINGS_FAILURE,
  GET_ACTIVE_FAMILIES_REQUEST,
  GET_ACTIVE_FAMILIES_SUCCESS,
  GET_ACTIVE_FAMILIES_FAILURE,
  UPDATE_THREAT_FIELD,
  DELETE_THREAT_REQUEST,
  DELETE_THREAT_SUCCESS,
  DELETE_THREAT_FAILURE,
  GET_SOURCE_REQUEST,
  GET_SOURCE_SUCCESS,
  GET_SOURCE_FAILURE,
} from './constants';

const initialTenantStorage = store.get(StorageEnum.TENANT) || {
  enabled: false,
  data: [],
};

const initialTimeSpanStorage = store.get(StorageEnum.TIMESPAN) || {
  startDate: moment()
    .subtract(1, 'day')
    .format(),
  endDate: moment().format(),
  duration: 'H1',
  timePicker: TimePickerEnum.QUICK,
};

const initialSourceStorage = store.get(StorageEnum.SOURCE) || [];

const initialFiltersStorage = getQueryObject();

export const singleActiveThreatObject = {
  first_seen: '',
  last_seen: '',
  nb_assets: 0,
  pk: 0,
};

// The initial state of the App
export const initialState = {
  timespan: {
    ...initialTimeSpanStorage,
  },
  tenant: {
    ...initialTenantStorage,
    request: {
      loading: null,
      status: null,
      message: '',
    },
  },
  settings: {
    data: {},
    request: {
      loading: null,
      status: null,
      message: '',
    },
  },
  reload: {
    period: ReloadPeriodEnum.NONE,
    now: 0,
  },
  families: {
    active: {
      data: [],
      request: {
        loading: null,
        status: null,
        message: '',
      },
    },
    list: {
      data: [],
      request: {
        loading: null,
        status: null,
        message: '',
      },
    },
  },
  user: {
    data: {},
    request: {
      loading: null,
      status: null,
      message: '',
    },
  },
  threats: {
    active: {
      data: {},
      request: {
        loading: null,
        status: null,
        message: '',
      },
    },
    list: {
      data: [],
      request: {
        loading: null,
        status: null,
        message: '',
      },
    },
    all: {
      data: [],
      request: {
        loading: null,
        status: null,
        message: '',
      },
    },
    delete: {
      request: {
        loading: false,
        status: null,
        message: '',
      },
    },
  },
  filters: {
    ...initialFiltersStorage,
  },
  source: {
    data: [...initialSourceStorage],
    request: {
      loading: false,
      status: null,
      message: '',
    },
  },
};

/* eslint-disable default-case */
const appReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case GET_GLOBAL_SETTINGS_REQUEST:
        draft.settings.request.loading = true;
        draft.settings.request.status = null;
        draft.settings.request.message = '';
        break;
      case GET_GLOBAL_SETTINGS_SUCCESS: {
        const { multi_tenancy: multiTenancy = false } = action.payload.data;
        draft.settings.data = action.payload.data;
        draft.settings.request.loading = false;
        draft.settings.request.status = true;
        draft.settings.request.message = '';
        if (multiTenancy !== initialTenantStorage.enabled) {
          draft.tenant.enabled = multiTenancy;
          store.set(StorageEnum.TENANT, {
            ...(store.get(StorageEnum.TENANT) || initialTenantStorage),
            enabled: multiTenancy,
          });
        }
        break;
      }
      case GET_GLOBAL_SETTINGS_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.settings.request.loading = false;
        draft.settings.request.status = false;
        draft.settings.request.message = `Global settings could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case GET_FAMILIES_REQUEST:
        draft.families.list.request.loading = true;
        draft.families.list.request.status = null;
        draft.families.list.request.message = '';
        break;
      case GET_FAMILIES_SUCCESS:
        draft.families.list.data = action.payload.families;
        draft.families.list.request.loading = false;
        draft.families.list.request.status = true;
        draft.families.list.request.message = '';
        break;
      case GET_FAMILIES_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.families.list.request.loading = false;
        draft.families.list.request.status = false;
        draft.families.list.request.message = `Families could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case GET_ACTIVE_FAMILIES_REQUEST:
        draft.families.active.request.loading = true;
        draft.families.active.request.status = null;
        draft.families.active.request.message = '';
        break;
      case GET_ACTIVE_FAMILIES_SUCCESS:
        draft.families.active.data = action.payload.families;
        draft.families.active.request.loading = false;
        draft.families.active.request.status = true;
        draft.families.active.request.message = '';
        break;
      case GET_ACTIVE_FAMILIES_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.families.active.request.loading = false;
        draft.families.active.request.status = false;
        draft.families.active.request.message = `Active families could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case GET_USER_REQUEST:
        draft.user.request.loading = true;
        draft.user.request.status = null;
        draft.user.request.message = '';
        break;
      case GET_USER_SUCCESS:
        draft.user.data = {
          allTenant: action.payload.all_tenant,
          noTenant: action.payload.no_tenant,
          tenants: action.payload.tenants,
          pk: action.payload.pk,
          timezone: action.payload.timezone,
          username: action.payload.username,
          firstName: action.payload.first_name,
          lastName: action.payload.last_name,
          isActive: action.payload.is_active,
          email: action.payload.email,
          dateJoined: action.payload.date_joined,
          permissions: action.payload.perms,
        };

        draft.user.request.loading = false;
        draft.user.request.status = true;
        draft.user.request.message = '';
        break;
      case GET_USER_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.user.data = {};
        draft.user.request.loading = false;
        draft.user.request.status = false;
        draft.user.request.message = `User could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case GET_THREATS_REQUEST:
        draft.threats.list.request.loading = true;
        draft.threats.list.request.status = null;
        draft.threats.list.request.message = '';
        break;
      case GET_THREATS_SUCCESS:
        draft.threats.list.data = action.payload.threats;
        draft.threats.list.request.loading = false;
        draft.threats.list.request.status = true;
        draft.threats.list.request.message = '';
        break;
      case GET_THREATS_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.threats.list.data = [];
        draft.threats.list.request.loading = false;
        draft.threats.list.request.status = false;
        draft.threats.list.request.message = `Threats could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case GET_ACTIVE_THREATS_REQUEST:
        draft.threats.active.request.loading = true;
        draft.threats.active.request.status = null;
        draft.threats.active.request.message = '';
        break;
      case GET_ACTIVE_THREATS_SUCCESS: {
        const { activeThreats, familyId } = action.payload;
        draft.threats.active.data[familyId] =
          activeThreats.length === 0
            ? [singleActiveThreatObject]
            : activeThreats.map(o => ({
                pk: o.pk,
                nb_assets: o.nb_assets,
                first_seen: o.first_seen,
                last_seen: o.last_seen,
              }));
        draft.threats.active.request.loading = false;
        draft.threats.active.request.status = true;
        draft.threats.active.request.message = '';
        break;
      }
      case GET_ACTIVE_THREATS_FAILURE: {
        const { httpCode, httpError, httpResponse, familyId } = action.payload;
        draft.threats.active.data[familyId] = [];
        draft.threats.active.request.loading = false;
        draft.threats.active.request.status = false;
        draft.threats.active.request.message = `Active threats could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case GET_TENANTS_REQUEST:
        draft.tenant.data = [];
        draft.tenant.request.loading = true;
        draft.tenant.request.status = null;
        draft.tenant.request.message = '';
        break;
      case GET_TENANTS_SUCCESS:
        draft.tenant.data = action.payload.tenants.map(t => ({ ...t, key: t.pk }));
        draft.tenant.request.loading = false;
        draft.tenant.request.status = true;
        draft.tenant.request.message = '';
        store.set(StorageEnum.TENANT, {
          ...(store.get(StorageEnum.TENANT) || initialTenantStorage),
          data: action.payload.tenants,
        });
        break;
      case GET_TENANTS_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.tenant.data = [];
        draft.tenant.request.loading = false;
        draft.tenant.request.status = false;
        draft.tenant.request.message = `Active threats could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case GET_SOURCE_REQUEST:
        draft.source.data = [];
        draft.source.request.loading = true;
        draft.source.request.status = null;
        draft.source.request.message = '';
        break;
      case GET_SOURCE_SUCCESS:
        draft.source.data = action.payload.source;
        draft.source.request.loading = false;
        draft.source.request.status = true;
        draft.source.request.message = '';
        store.set(StorageEnum.SOURCE, [...action.payload.source]);
        break;
      case GET_SOURCE_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.source.data = [];
        draft.source.request.loading = false;
        draft.source.request.status = false;
        draft.source.request.message = `Sources could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case DELETE_THREAT_REQUEST: {
        draft.threats.delete.request = {
          loading: true,
          status: null,
          message: '',
        };
        break;
      }
      case DELETE_THREAT_SUCCESS: {
        draft.threats.delete.request = {
          loading: false,
          status: true,
          message: 'Threat has been successfully deleted',
        };
        const { threatId } = action.payload;
        draft.threats.list.data = draft.threats.list.data.filter(t => t.pk !== threatId);
        const familyIds = Object.keys(draft.threats.active.data);
        for (let i = 0; i < familyIds.length; i += 1) {
          draft.threats.active.data[familyIds[i]] = draft.threats.active.data[familyIds[i]].filter(t => t.pk !== threatId);
        }
        break;
      }
      case DELETE_THREAT_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.threats.delete.request = {
          loading: true,
          status: null,
          message: `Threat could not be deleted.\\n${httpCode} ${httpError}\\n ${httpResponse}`,
        };
        break;
      }
      case SET_TIME_SPAN: {
        const { startDate, endDate } = action;
        draft.reload.now = new Date().getTime();
        draft.timespan.startDate = startDate;
        draft.timespan.endDate = endDate;
        draft.timespan.timePicker = TimePickerEnum.ABSOLUTE;
        store.set(StorageEnum.TIMESPAN, {
          ...(store.get(StorageEnum.TIMESPAN) || initialTimeSpanStorage),
          timePicker: TimePickerEnum.ABSOLUTE,
          startDate,
          endDate,
        });
        break;
      }
      case SET_DURATION: {
        const { duration } = action;
        draft.timespan.duration = duration;
        draft.timespan.timePicker = TimePickerEnum.QUICK;
        store.set(StorageEnum.TIMESPAN, {
          ...(store.get(StorageEnum.TIMESPAN) || initialTimeSpanStorage),
          timePicker: TimePickerEnum.QUICK,
          duration,
        });
        break;
      }
      case SET_RELOAD: {
        draft.reload.period = action.payload.reloadPeriod;
        break;
      }
      case DO_RELOAD: {
        draft.reload.now = new Date().getTime();
        break;
      }
      case UPDATE_THREAT_FIELD: {
        const { threatId, field, value } = action.payload;
        draft.threats.list.data = draft.threats.list.data.map(v => (v.pk === threatId ? { ...v, [field]: value } : v));
        break;
      }
      case LOCATION_CHANGE: {
        if (isBooted()) {
          draft.filters = parseUrl(history.location.search);
          store.set(StorageEnum.FILTERS, parseUrl(history.location.search));
        } else {
          if (isEqual(parseUrl(history.location.search), initialFiltersStorage)) {
            store.set(StorageEnum.FILTERS, parseUrl(history.location.search));
          }
          setBooted(true);
        }
        break;
      }
    }
  });

export default appReducer;
