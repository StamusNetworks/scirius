import { makeAutoObservable } from 'mobx';
import moment from 'moment';

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

  constructor(root) {
    this.root = root;
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

  addFilter(filter) {
    this.ids = [...this.ids, filter];
  }
}

export default CommonStore;
