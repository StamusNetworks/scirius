import { message } from 'antd';
import { isEqual } from 'lodash';
import { makeAutoObservable, toJS } from 'mobx';
import moment from 'moment';

import endpoints from 'ui/config/endpoints';
import Filter from 'ui/utils/Filter';

import { PeriodEnum } from '../../maps/PeriodEnum';
import { api } from '../api';

import { createFilterInstanceFromStorage, getEventTypesToTurnOn, getFilters } from './CommonStore.util';

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

  history = [];

  _alert = {};

  _systemSettings = null;

  _sources = [];

  _user = null;

  _withAlerts = null;

  _stickyFilters = true;

  _linkTemplates = [];

  constructor(root) {
    this.root = root;
    if (!localStorage.getItem('alert_tag')) {
      this._alert = CommonStore.generateAlert();
      localStorage.setItem('alert_tag', JSON.stringify(toJS(this._alert)));
    } else {
      try {
        this._alert = JSON.parse(localStorage.getItem('alert_tag'));
      } catch (e) {
        // eslint-disable-next-line no-console
        console.log('Error while parsing local storage data');
      }
    }
    if (!localStorage.getItem('withAlerts')) {
      localStorage.setItem('withAlerts', 'true');
      this._withAlerts = true;
    } else {
      try {
        this._withAlerts = !!JSON.parse(localStorage.getItem('withAlerts'));
        localStorage.setItem('withAlerts', JSON.stringify(this._withAlerts));
      } catch (e) {
        this._withAlerts = true;
        localStorage.setItem('withAlerts', 'true');
        // eslint-disable-next-line no-console
        console.log('Error while parsing local storage data');
      }
    }
    try {
      this._systemSettings = JSON.parse(localStorage.getItem('str-system-settings'));
      this._sources = JSON.parse(localStorage.getItem('str-sources') || '[]');
      this._timeRangeType = JSON.parse(localStorage.getItem('str-timespan') || '{}')?.timePicker || 'relative';
      this._relativeType = JSON.parse(localStorage.getItem('str-timespan') || '{}')?.duration || 'H1';
      this.ids = JSON.parse(localStorage.getItem('ids_filters') || '[]').map(createFilterInstanceFromStorage);
      this.history = JSON.parse(localStorage.getItem('history_filters') || '[]').map(
        ({ id, value, negated, fullString, uuid }) => new Filter(id, value, { uuid, negated, fullString }),
      );
    } catch (e) {
      // eslint-disable-next-line no-console
      console.log('Error while parsing local storage data');
    }
    const storedStartDate = localStorage.getItem('startDate');
    const storedEndDate = localStorage.getItem('endDate');
    if (!storedStartDate || !storedEndDate) {
      this._timeRangeType = 'relative';
      this._relativeType = 'H1';
      this._startDate = moment().subtract(1, 'hours').unix();
      this._endDate = moment().unix();
    } else if (this._timeRangeType === 'absolute') {
      this._startDate = Number(storedStartDate);
      this._endDate = Number(storedEndDate);
    } else {
      this._relativeType = JSON.parse(localStorage.getItem('str-timespan') || '{}')?.duration || 'H1';
      if (this._relativeType === 'Auto') {
        this._startDate = this._minTimestamp;
        this._endDate = this._maxTimestamp;
      } else {
        this._startDate = moment().subtract(PeriodEnum[this._relativeType].seconds, 'seconds').unix();
        this._endDate = moment().unix();
      }
    }
    makeAutoObservable(this, {
      root: false,
    });
  }

  /* Setters */
  /**
   * Sets a relative time range
   * @param {'H1','H6','H24','D2','D7','D30','Y1','All', 'Auto'} type
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
        this._startDate = 0;
        break;
      case 'Auto':
        this._startDate = moment(this._minTimestamp).unix();
        this._endDate = moment(this._maxTimestamp).unix();
        break;
      default:
        break;
    }
    if (type !== 'Auto') {
      this._endDate = moment().unix();
    }
    this._timeRangeType = 'relative';
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
      this.setTimePickerStorage();
    }
  }

  async fetchSignatures(listParams) {
    const response = await api.get(`${endpoints.SIGNATURES.url}?${listParams}`);
    return response;
  }

  async fetchSignature(sid) {
    const response = await api.get(`${endpoints.SIGNATURE.url}`, { sid });
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
      const { max_timestamp: maxValue, min_timestamp: minValue } = response.data;
      const minTimestamp = parseInt(minValue, 10);
      const maxTimestamp = parseInt(maxValue, 10);
      const correct = !Number.isNaN(minTimestamp) && !Number.isNaN(maxTimestamp);

      // If the difference between min and max timestamp is less than a week, set the default period to D7
      if (!correct || maxTimestamp - minTimestamp < 60 * 60 * 24 * 7) {
        this._minTimestamp = null;
        this._maxTimestamp = null;
      } else {
        this._minTimestamp = minTimestamp;
        this._maxTimestamp = maxTimestamp;
      }
      this.setTimePickerStorage();
    }
  }

  async fetchElasticSearch(params, timeFilter) {
    const response = await api.post(endpoints.ELASTIC_SEARCH.url, { ...params, time_filter: timeFilter });
    return response;
  }

  // @TODO: Should be handled better (skipCheck)
  addFilter(stack) {
    const filters = getFilters(stack);

    // Update existing filters that if key/value is the same
    this.ids = this.ids.map(f => {
      const matchingFilter = filters.find(id => id.id === f.id && id.value === f.value);
      const sameIdDifferentValueFilter = filters.find(id => id.id === f.id && id.value !== f.value);
      const isSameFilter = matchingFilter && matchingFilter.negated === f.negated && matchingFilter.fullString === f.fullString;

      if (sameIdDifferentValueFilter && f.unique) {
        f.suspended = true;
        return f;
      }

      if (!matchingFilter) return f;

      if (isSameFilter) {
        f.suspended = false;
        return f;
      }

      f.suspended = false;
      f.negated = matchingFilter.negated;
      f.fullString = matchingFilter.fullString;

      message.info({
        content: `Filter updated!`,
      });

      return f;
    });

    // ADD Only new filters
    const newFilters = filters.filter(f => !this.ids.some(id => id.id === f.id && id.value === f.value));
    this.ids.push(...newFilters);
    if (newFilters.length > 0) {
      message.info({
        content: `Filter added!`,
      });
    }

    // PERSIST to localStorage
    localStorage.setItem('ids_filters', JSON.stringify(toJS(this.ids.map(f => f.toJSON()))));

    // Set each EVENT_TYPE from force array to true
    const eventTypesToTurnOn = getEventTypesToTurnOn(filters);
    eventTypesToTurnOn.forEach(eventType => {
      this.setAlertTag(eventType, true);
    });
  }

  /**
   *
   * @param stack - Set the current filters with the new ones
   */
  setFilters(stack) {
    const filters = getFilters(stack);
    this.ids = filters;
    localStorage.setItem('ids_filters', JSON.stringify(toJS(this.ids.map(f => f.toJSON()))));

    // Set each EVENT_TYPE from force array to true
    const eventTypesToTurnOn = getEventTypesToTurnOn(filters);
    eventTypesToTurnOn.forEach(eventType => {
      this.setAlertTag(eventType, true);
    });

    // notify the user only when Filters component is not shown
    message.info({
      content: `Filter${filters.length > 0 ? 's' : ''} set!`,
    });
  }

  addHistoryFilter(filter) {
    if (filter instanceof Filter) {
      this.history = [...this.history, filter];
      localStorage.setItem('history_filters', JSON.stringify(toJS(this.history.map(f => f.toJSON()))));
    }
  }

  removeFilter(uuid) {
    this.ids = this.ids.filter(f => f._uuid !== uuid);
    localStorage.setItem('ids_filters', JSON.stringify(toJS(this.ids.map(f => f.toJSON()))));
  }

  removeHistoryFilter(uuid) {
    this.history = this.history.filter(f => f._uuid !== uuid);
    localStorage.setItem('history_filters', JSON.stringify(toJS(this.history.map(f => f.toJSON()))));
  }

  clearFilters() {
    this.ids = [];
    localStorage.setItem('ids_filters', '[]');
  }

  nextFilters(filters) {
    this.ids = this.ids.map(f => {
      f.suspended = true;
      return f;
    });
    this.addFilter(filters);
  }

  getFilters(includeAlertTAg = false) {
    if (includeAlertTAg) {
      return [...toJS(this.ids), toJS(this._alert)].filter(Boolean);
    }
    return toJS(this.ids);
  }

  async fetchLinkTemplates() {
    const response = await api.get(endpoints.DEEPLINK.url);
    if (response.ok) {
      this._linkTemplates = response.data.results;
    }
  }

  get linkTemplates() {
    return this._linkTemplates;
  }

  set withAlerts(value) {
    if (value) {
      const hitsMin = this.ids.find(f => f.id === 'hits_min');
      if (hitsMin) {
        if (hitsMin.value > 1) {
          localStorage.setItem('hitsMinBackup', JSON.stringify(hitsMin.toJSON()));
        }
        this.ids = this.ids.filter(f => f.id !== 'hits_min');
        // localStorage.setItem('ids_filters', JSON.stringify(this.ids.map(({ instance }) => instance)));
      }
    } else {
      let backup;
      try {
        const jsBackup = JSON.parse(localStorage.getItem('hitsMinBackup'));
        if (jsBackup) {
          backup = new Filter(jsBackup.id, jsBackup.value, { negated: jsBackup.negated });
        }
        localStorage.removeItem('hitsMinBackup');
      } catch (e) {
        // eslint-disable-next-line no-console
        console.log('Error parsing backed up hits_min filter');
      }

      if (backup) {
        this.addFilter(backup);
      }
    }

    localStorage.setItem('withAlerts', value);
    this._withAlerts = value;
  }

  get withAlerts() {
    return this._withAlerts;
  }

  get startDate() {
    if (this._timeRangeType === 'absolute') {
      return this._startDate;
    }
    if (this._relativeType === 'All') {
      return 0;
    }
    if (this._relativeType === 'Auto') {
      // D7 period is the default one if min/max timestamp boundaries are incorrect
      return moment(this._minTimestamp).unix() || moment().subtract(7, 'days').unix();
    }
    return moment().subtract(PeriodEnum[this._relativeType].seconds, 'seconds').unix();
  }

  get endDate() {
    if (this._relativeType === 'Auto') {
      // D7 period is the default one if min/max timestamp boundaries are incorrect
      return moment(this._maxTimestamp).unix() || moment().unix();
    }
    return this._endDate;
  }

  get refresh() {
    return this._refresh;
  }

  get refreshTime() {
    return this._refreshTime;
  }

  get filters() {
    return this.ids;
  }

  get systemSettings() {
    return toJS(this._systemSettings);
  }

  toggleAlertTag(key) {
    this._alert = { ...this._alert, value: { ...this._alert.value, [key]: !this._alert.value[key] } };
    localStorage.setItem('alert_tag', JSON.stringify(toJS(this._alert)));
  }

  setAlertTag(alert, value) {
    this._alert = { ...this._alert, value: { ...this._alert.value, [alert]: value } };
    localStorage.setItem('alert_tag', JSON.stringify(toJS(this._alert)));
  }

  set stickyFilters(value) {
    this._stickyFilters = value;
  }

  get stickyFilters() {
    return toJS(this._stickyFilters);
  }

  get alert() {
    return this._alert;
  }

  get eventTypes() {
    return { alert: toJS(this._alert.value.alerts), stamus: toJS(this._alert.value.stamus), discovery: !!toJS(this._alert.value.sightings) };
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
    if (this._timeRangeType === 'relative') {
      this.setRelativeTimeRange(this._relativeType);
    }
    this._refresh = moment().unix();
  }

  setRefreshTime(value) {
    this._refreshTime = value;
  }

  setTimePickerStorage() {
    localStorage.setItem('startDate', this._startDate);
    localStorage.setItem('endDate', this._endDate);
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

  static indexOfFilter(filter, allFilters) {
    for (let idx = 0; idx < allFilters.length; idx += 1) {
      if (
        allFilters[idx].label === filter.label &&
        allFilters[idx].id === filter.id &&
        allFilters[idx].value === filter.value &&
        allFilters[idx].negated === filter.negated &&
        allFilters[idx].fullString === filter.fullString
      ) {
        return idx;
      }
    }
    return -1;
  }

  static generateAlert(informational = false, relevant = true, untagged = true, alerts = true, sightings = true, stamus = true) {
    return {
      id: 'alert.tag',
      value: { informational, relevant, untagged, alerts, sightings, stamus },
    };
  }

  static validateFilter(filter) {
    if (filter.id === 'alert.tag') {
      // eslint-disable-next-line no-console
      console.error('Tags must go in a separate store');
      return false;
    }

    const filterProps = ['id', 'value', 'negated', 'label', 'fullString'];
    for (let i = 0; i < filterProps.length; i += 1) {
      if (!(filterProps[i] in filter)) {
        return false;
      }
    }
    return true;
  }
}

export default CommonStore;
