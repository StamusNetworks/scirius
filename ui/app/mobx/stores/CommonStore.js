import { makeAutoObservable, toJS } from 'mobx';
import moment from 'moment';
import endpoints from 'ui/config/endpoints';
import { isEqual } from 'lodash';
import { api } from '../api';
import { PeriodEnum } from '../../maps/PeriodEnum';

class CommonStore {
  root = null;

  // @TODO: Expose the time management stuff to a separate store
  /**
   * Time range type absolute | relative
   * @type {string}
   */
  _timeRangeType = 'relative';

  /**
   * Value when timeRangeType is set to relative
   * @type {string}
   */
  _relativeType = 'H1';

  /**
   * Start time value when timeRangeType is set to absolute
   * @type {number | null}
   */
  _startDate = null;

  /**
   * End time value when timeRangeType is set to absolute
   * @type {number | null}
   */
  _endDate = null;

  /**
   * Minimum available timestamp for 'All' type
   * @type {number | null}
   */
  _minTimestamp = null;

  /**
   * Maximum available timestamp for 'All' type
   * @type {number | null}
   */
  _maxTimestamp = null;

  /**
   * Automatic reload
   * @type {boolean | null}
   */
  _refresh = null;

  /**
   * Automatic reload time
   * @type {boolean | null}
   */
  _refreshTime = null;

  ids = [];

  alert = {};

  _systemSettings = null;

  _sources = [];

  _user = null;

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
      this._startDate = startDate;
      localStorage.setItem('startDate', startDate);
    } else {
      this._startDate = localStorage.getItem('startDate');
    }
    if (!localStorage.getItem('endDate')) {
      const endDate = moment().unix();
      this._endDate = endDate;
      localStorage.setItem('endDate', endDate);
    } else {
      this._endDate = localStorage.getItem('endDate');
    }
    try {
      this._systemSettings = JSON.parse(localStorage.getItem('str-system-settings'));
      this.ids = JSON.parse(localStorage.getItem('ids_filters') || '[]');
      this._sources = JSON.parse(localStorage.getItem('str-sources') || '[]');
      this._timeRangeType = JSON.parse(localStorage.getItem('str-timespan') || '{}')?.timePicker || 'relative';
      this._relativeType = JSON.parse(localStorage.getItem('str-timespan') || '{}')?.duration || 'H1';
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
        this._startDate = moment().subtract(1, 'hour').unix();
        break;
      case 'H6':
        this._startDate = moment().subtract(6, 'hours').unix();
        break;
      case 'H24':
        this._startDate = moment().subtract(24, 'hours').unix();
        break;
      case 'D2':
        this._startDate = moment().subtract(2, 'days').unix();
        break;
      case 'D7':
        this._startDate = moment().subtract(7, 'days').unix();
        break;
      case 'D30':
        this._startDate = moment().subtract(30, 'days').unix();
        break;
      case 'Y1':
        this._startDate = moment().subtract(1, 'year').unix();
        break;
      case 'All':
        break;
      default:
        break;
    }
    this._endDate = moment().unix();
    this._timeRangeType = 'relative';
    localStorage.setItem('startDate', this._startDate);
    localStorage.setItem('endDate', this._endDate);
    this._relativeType = type;
    this.setTimePickerStorage();
  }

  /**
   * Sets an absolute time range
   * @param {number} startDate
   * @param {number} endDate
   */
  setAbsoluteTimeRange(startDate, endDate) {
    if (startDate < endDate) {
      this._startDate = startDate;
      this._endDate = endDate;
      this._timeRangeType = 'absolute';
      localStorage.setItem('startDate', startDate);
      localStorage.setItem('endDate', endDate);
      this.setTimePickerStorage();
    }
  }

  async fetchSignatures(listParams) {
    const response = await api.get(`${endpoints.SIGNATURES.url}?highlight=true&${listParams}`);
    return response;
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
        const object1 = this.sources;
        const object2 = response.data?.results;

        if (!localSources || !isEqual(object1, object2)) {
          this._sources = response.data?.results || [];
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
      this._user = {
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

  async fetchContext() {
    const response = await api.get(endpoints.SCIRIUS_CONTEXT.url);
    return response;
  }

  async fetchRuleset() {
    const response = await api.get(endpoints.RULE_SETS.url);
    return response;
  }

  async fetchAllPeriod() {
    const response = await api.get(endpoints.ALL_PERIOD.url, { event_view: false });
    if (response.ok) {
      const { max_timestamp: maxTimestamp = 0, min_timestamp: minTimestamp = 0 } = response.data;

      const correct = !Number.isNaN(parseInt(response.data.max_timestamp, 10)) && !Number.isNaN(parseInt(response.data.min_timestamp, 10));
      if (!correct) {
        this._minTimestamp = null;
        this._maxTimestamp = null;
        if (this._relativeType === 'All') {
          this._relativeType = 'D7';
        }
      } else {
        this._minTimestamp = minTimestamp;
        this._maxTimestamp = maxTimestamp;
      }
      this.setTimePickerStorage();
    }
  }

  // @TODO: Should be handled better (skipCheck)
  addFilter(filter) {
    const stack = Array.isArray(filter) ? filter : [filter];
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
      localStorage.setItem('ids_filters', JSON.stringify(toJS(filtersUpdated)));
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

  get startDate() {
    if (this._timeRangeType === 'absolute') {
      return this._startDate;
    }
    if (this._relativeType === 'All') {
      // D7 period is the default one if min/max timestamp boundaries are incorrect
      return !Number.isNaN(parseInt(this._minTimestamp, 10)) ? moment(this._minTimestamp).unix() : moment().subtract(7, 'days');
    }
    return moment().subtract(PeriodEnum[this._relativeType].seconds, 'milliseconds').unix();
  }

  get endDate() {
    if (this._relativeType === 'All') {
      // D7 period is the default one if min/max timestamp boundaries are incorrect
      return !Number.isNaN(parseInt(this._maxTimestamp, 10)) ? moment(this._maxTimestamp).unix() : moment();
    }
    return parseInt(this._endDate, 10);
  }

  get refresh() {
    return this._refresh;
  }

  get refreshTime() {
    return this._refresh;
  }

  get filters() {
    return [...toJS(this.ids)].filter(Boolean);
  }

  get filtersWithAlert() {
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

  get sources() {
    return toJS(this._sources);
  }

  get user() {
    return toJS(this._user);
  }

  get disableAll() {
    return !this._minTimestamp || !this._maxTimestamp;
  }

  get timeRangeType() {
    return this._timeRangeType;
  }

  get relativeType() {
    return this._relativeType;
  }

  reload() {
    this._refresh = moment().unix();
  }

  setRefreshTime(value) {
    this._refreshTime = value;
  }

  setTimePickerStorage() {
    localStorage.setItem(
      'str-timespan',
      JSON.stringify({
        disableAll: this.disableAll,
        duration: this.relativeType,
        endDate: this.endDate,
        maxTimestamp: this._maxTimestamp,
        minTimestamp: this._minTimestamp,
        startDate: this.startDate,
        timePicker: this._timeRangeType,
      }),
    );
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
