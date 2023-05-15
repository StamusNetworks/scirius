import { makeAutoObservable } from 'mobx';
import { api } from '../api';

class CommonStore {
  root = null;

  /* DateTime related data */

  /**
   * Available relative time ranges
   * @type {{D30: {seconds: number, name: string, title: string}, All: {name: string, title: string}, D7: {seconds: number, name: string, title: string}, Y1: {seconds: number, name: string, title: string}, H1: {seconds: number, name: string, title: string}, H24: {seconds: number, name: string, title: string}, H6: {seconds: number, name: string, title: string}, D2: {seconds: number, name: string, title: string}}}
   */
  #periods = {
    H1: {
      name: 'last 1h',
      title: 'last 1 hour',
      seconds: 3600000,
    },
    H6: {
      name: 'last 6h',
      title: 'last 6 hours',
      seconds: 21600000,
    },
    H24: {
      name: 'last 24h',
      title: 'last 24 hours',
      seconds: 86400000,
    },
    D2: {
      name: 'last 2d',
      title: 'last 2 days',
      seconds: 172800000,
    },
    D7: {
      name: 'last 7d',
      title: 'last 7 days',
      seconds: 604800000,
    },
    D30: {
      name: 'last 30d',
      title: 'last 30 days',
      seconds: 2592000000,
    },
    Y1: {
      name: 'last 1y',
      title: 'last 1 year',
      seconds: 31536000000,
    },
    All: {
      name: 'All',
      title: 'All',
      /* REMAINDER: Please don't use .seconds directly from this enumerator */
    },
  };

  /**
   * Available time range types
   * @type {string[]}
   */
  #timeRangeTypes = ['absolute', 'relative'];

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
  #absoluteStartTime = null;

  /**
   * End time value when timeRangeType is set to absolute
   * @type {number | null}
   */
  #absoluteEndTime = null;

  constructor(root) {
    this.root = root;
    makeAutoObservable(this, {
      root: false,
    });
    this.fetchAllPeriod();
  }

  /* Fetchers */
  async fetchAllPeriod() {
    const response = await api.get(`/es/alerts_timerange/${this.root.tenantStore.getTenantParam('?')}`);
    if (response.ok) {
      console.log('fetchAllPeriod >', response.data);
      // this.historyItemsList = response.data.results;
      // this.historyItemsCount = response.data.count;
    }
    return response;
  }

  /* Setters */

  /**
   * Sets the value of the start date
   * @param {number} value
   */
  #setStartDate(value) {
    this.startDate = value;
  }

  /**
   * Sets the value of the end date
   * @param {number} value
   */
  #setEndDate(value) {
    this.endDate = value;
  }

  /**
   * Sets a relative time range
   * @param {'absolut'|'relative'} type
   */
  setRelativeTimeRange(type) {
    if (this.#timeRangeType.includes(type)) {
      this.timeRangeType = type;
    }
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

  /* Getters */

  /**
   * Get the start date of the currently selected time range regardless the type of the time range
   * @returns {number}
   */
  getStartDate() {
    return this.startDate;
  }

  /**
   * Get the end date of the currently selected time range regardless the type of the time range
   * @returns {number}
   */
  getEndDate() {
    return this.endDate;
  }
}

export default CommonStore;
