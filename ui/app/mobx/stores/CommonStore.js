import { makeAutoObservable, toJS } from 'mobx';
import moment from 'moment';
import endpoints from 'ui/config/endpoints';
import { isEqual } from 'lodash';
import { api } from '../api';

class CommonStore {
  root = null;

  /* Time range type absolute | relative */
  #timeRangeType = 'relative';

  /**
   * Value when timeRangeType is set to relative
   * @type {string}
   */
  #relative = '1H';

  /**
   * Start time value when timeRangeType is set to absolute
   * @type {number | null}
   */
  startDate = null;

  /**
   * End time value when timeRangeType is set to absolute
   * @type {number | null}
   */
  endDate = null;

  ids = [];

  alert = {};

  _systemSettings = null;

  sources = null;

  user = null;

  constructor(root) {
    this.root = root;
    if (!localStorage.getItem('alert_tag')) {
      this.alert = CommonStore.generateAlert();
      localStorage.setItem('alert_tag', JSON.stringify(toJS(this.alert)));
    } else {
      try {
        this.alert = JSON.parse(localStorage.getItem('alert_tag'));
      } catch (e) {
        // eslint-disable-next-line no-console
        console.log('Error while parsing local storage data');
      }
    }
    if (!localStorage.getItem('startDate')) {
      const startDate = moment().subtract(1, 'hours').unix();
      this.startDate = startDate;
      localStorage.setItem('startDate', startDate);
    } else {
      this.startDate = localStorage.getItem('startDate');
    }
    if (!localStorage.getItem('endDate')) {
      const endDate = moment().unix();
      this.endDate = endDate;
      localStorage.setItem('endDate', endDate);
    } else {
      this.endDate = localStorage.getItem('endDate');
    }
    try {
      this._systemSettings = JSON.parse(localStorage.getItem('str-system-settings'));
      this.ids = JSON.parse(localStorage.getItem('ids_filters') || '[]');
      this.sources = JSON.parse(localStorage.getItem('str-sources') || '[]');
    } catch (e) {
      // eslint-disable-next-line no-console
      console.log('Error while parsing local storage data');
    }
    makeAutoObservable(this, {
      root: false,
    });
  }

  /* Setters */
  /**
   * Sets a relative time range
   * @param {'H1','H6','H24','D2','D7','D30','Y1','All'} type
   */
  setRelativeTimeRange(type) {
    switch (type) {
      case 'H1':
        this.startDate = moment().subtract(1, 'hours').unix();
        break;
      case 'H6':
        this.startDate = moment().subtract(6, 'hours').unix();
        break;
      case 'H24':
        this.startDate = moment().subtract(24, 'hours').unix();
        break;
      case 'D2':
        this.startDate = moment().subtract(2, 'days').unix();
        break;
      case 'D7':
        this.startDate = moment().subtract(7, 'days').unix();
        break;
      case 'D30':
        this.startDate = moment().subtract(30, 'days').unix();
        break;
      case 'Y1':
        this.startDate = moment().subtract(1, 'years').unix();
        break;
      case 'All':
        break;
      default:
        break;
    }
    this.endDate = moment().unix();
    this.timeRangeType = 'relative';
    localStorage.setItem('startDate', this.startDate);
    localStorage.setItem('endDate', this.endDate);
    this.relative = type;
  }

  /**
   * Sets an absolute time range
   * @param {number} startDate
   * @param {number} endDate
   */
  setAbsoluteTimeRange(startDate, endDate) {
    if (startDate < endDate) {
      this.startDate = startDate;
      this.endDate = endDate;
    }
  }

  async fetchSystemSettings() {
    const response = await api.get(endpoints.SYSTEM_SETTINGS.url);
    if (response.ok) {
      const localSystemSettings = localStorage.getItem('str-system-settings');
      try {
        if (!localSystemSettings || !isEqual(toJS(this._systemSettings), response.data)) {
          this._systemSettings = response.data;
          localStorage.setItem('str-system-settings', JSON.stringify(response.data));
        }
      } catch (e) {
        // eslint-disable-next-line no-console
        console.log('Error setting up system setting');
      }
    }
    return response;
  }

  async fetchSources() {
    const response = await api.get(endpoints.SOURCES.url, { datatype: 'threat' });
    if (response.ok) {
      const localSources = localStorage.getItem('str-sources');
      try {
        const object1 = this.getSources();
        const object2 = response.data?.results;

        if (!localSources || !isEqual(object1, object2)) {
          this.sources = response.data?.results || [];
          localStorage.setItem('str-sources', JSON.stringify(response.data?.results || []));
          localStorage.setItem('str-refresh', 'true');
        }
      } catch (e) {
        // eslint-disable-next-line no-console
        console.log('Error setting up sources');
      }
    }
    return response;
  }

  async fetchUser() {
    const response = await api.get(endpoints.CURRENT_USER.url);
    if (response.ok) {
      this.user = {
        allTenant: response.data.all_tenant,
        noTenant: response.data.no_tenant,
        tenants: response.data.tenants,
        pk: response.data.pk,
        timezone: response.data.timezone,
        username: response.data.username,
        firstName: response.data.first_name,
        lastName: response.data.last_name,
        isActive: response.data.is_active,
        email: response.data.email,
        dateJoined: response.data.date_joined,
        permissions: response.data.perms,
      };
    }
    return response;
  }

  addFilter(filter) {
    const stack = (Array.isArray(filter) ? filter : [filter]).filter(f => CommonStore.#validateFilter(f));
    this.ids = [...this.ids, ...stack];
    localStorage.setItem('ids_filters', JSON.stringify(toJS(this.ids)));
  }

  removeFilter(filter) {
    const filterIndex = CommonStore.#indexOfFilter(filter, this.ids);
    const before = this.ids.slice(0, filterIndex);
    const after = this.ids.slice(filterIndex + 1);
    this.ids = [...before, ...after];
    localStorage.setItem('ids_filters', JSON.stringify(toJS(this.ids)));
  }

  replaceFilter(oldFilter, newFilter) {
    if (CommonStore.#validateFilter(newFilter)) {
      const idx = CommonStore.#indexOfFilter(oldFilter, this.ids);

      /* eslint-disable-next-line */
      const filtersUpdated = this.ids.map((filter, i) => (i === idx) ? {
              ...filter,
              ...newFilter,
            }
          : filter,
      );
      this.ids = filtersUpdated;
      localStorage.setItem('ids_filters', JSON.stringify(toJS(this.ids)));
    }
  }

  clearFilters() {
    this.ids = [];
  }

  getFilters(includeAlertTAg = false) {
    if (includeAlertTAg) {
      return [...toJS(this.ids), toJS(this.alert)].filter(Boolean);
    }
    return toJS(this.ids);
  }

  get filters() {
    return [...toJS(this.ids)].filter(Boolean);
  }

  get filtersWithAlertTag() {
    return [...toJS(this.ids), toJS(this.alert)].filter(Boolean);
  }

  get systemSettings() {
    return toJS(this._systemSettings);
  }

  toggleAlertTag(key) {
    this.alert = { ...this.alert, value: { ...this.alert.value, [key]: !this.alert.value[key] } };
    localStorage.setItem('alert_tag', JSON.stringify(toJS(this.alert)));
  }

  get eventTypes() {
    return { alert: toJS(this.alert.value.alerts), stamus: toJS(this.alert.value.stamus), discovery: !!toJS(this.alert.value.sightings) };
  }

  getSources() {
    return toJS(this.sources);
  }

  getUser() {
    return toJS(this.user);
  }

  static #indexOfFilter(filter, allFilters) {
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

  static generateAlert(informational = true, relevant = true, untagged = true, alerts = true, sightings = true, stamus = false) {
    return {
      id: 'alert.tag',
      value: { informational, relevant, untagged, alerts, sightings, stamus },
    };
  }

  static #validateFilter(filter) {
    if (filter.id === 'alert.tag') {
      // eslint-disable-next-line no-console
      console.error('Tags must go in a separate store');
      return false;
    }

    const filterProps = ['id', 'value', 'negated', 'label', 'fullString', 'query'];

    const filterKeys = Object.keys(filter);
    for (let i = 0; i < filterKeys.length; i += 1) {
      if (!filterProps.includes(filterKeys[i])) {
        return false;
      }
    }
    return true;
  }
}

export default CommonStore;
