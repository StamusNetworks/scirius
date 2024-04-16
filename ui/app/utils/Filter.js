import { makeAutoObservable } from 'mobx';

import uuid from 'ui/helpers/uuid';
import { FilterCategory, FiltersList, FilterType } from 'ui/maps/Filters';

export default class Filter {
  /* Filter uuid */
  _uuid = null;

  /* Filter id. Example: alert.severity */
  _id = null;

  /* Filter raw value. Example: 1 */
  _value = null;

  /* Filter title. Example: Severity */
  _title = null;

  /* Filter label in filter bar. Example: Severity: Critical */
  _label = null;

  /* Filter category. Example: event | host */
  _category = FilterCategory.EVENT;

  /* Filter type: IP | PORT | MITRE | USERNAME | HOSTNAME | ROLE | GENERIC */
  _type = FilterType.GENERIC;

  /* Filter icon. ReactNode */
  _icon = null;

  /* Filter mode: including or excluding. Example: true | false */
  _negated = false;

  /* Filter mode: does it have a negated state. Example: true | false */
  _negatable = false;

  /* Filter mode: exact match. Example: true | false */
  _fullString = false;

  /* Filter mode: full string match. Example: true | false */
  _wildcardable = true;

  /* Filter is convertible to another one. Example: src_ip to host_id.ip */
  _convertible = false;

  /* Filter temporarily suspended */
  _suspended = false;

  _schema = null;

  /**
   * Initialize filter object by given parameters
   *
   * @example new Filter('signature', "ETPRO*", FilterCategory.EVENT, { fullString: false }
   * @example new Filter('signature', "ETPRO*", { fullString: false }
   * @param {string} filter -The ID of the filter
   * @param {string|number|boolean} value - The value of the filter
   * @param {object|string} a - filter parameters or filter category
   * @param {object} b - filter parameters if filter category is set on 3rd param
   * @returns {Filter}
   */
  constructor(filter, value, a = '', b = {}) {
    const props = typeof a === 'string' || Array.isArray(a) ? b : a || {};
    const filterSchema = this.findSchema(filter, a);

    if (!filterSchema && process.env.NODE_ENV === 'development') {
      // eslint-disable-next-line no-console
      console.warn(`Filter > ${filter} schema not found`);
    }

    // Read-only properties
    this._uuid = props?.uuid || uuid();
    this._id = filterSchema?.id || filter;
    this._value = value;
    this._title = filterSchema?.title || props?.title || filter;
    this._label = `${props?.title || filterSchema?.title || filter}: ${filterSchema?.format?.(value) || value}`;
    this._category = filterSchema?.category || Object.values(FilterCategory).find(c => c === a) || FilterCategory.EVENT;
    this._type = filterSchema?.type;
    this._negatable = this.prop(filterSchema?.negatable, true);
    this._wildcardable = this.prop(filterSchema?.wildcardable, true);
    this._convertible = this.prop(filterSchema?.convertible, false);
    this._schema = filterSchema;
    this._icon = filterSchema?.icon;

    const smartWildcard = this._wildcardable ? !/[\\*?]/.test(value) : null;
    // Overridable properties
    this._fullString = this.prop(props?.fullString, !this._schema?.defaults?.wildcard, smartWildcard, true);
    this._suspended = this.prop(props?.suspended, false);
    this._negated = this.prop(props?.negated, false);
    if (this._negated) {
      this.hookOnNegate();
    }

    makeAutoObservable(this);
  }

  findSchema(filter, a) {
    const category = typeof a === 'string' ? a : null;
    return FiltersList.find(f => f.id === filter && ((category && f.category === category) || true));
  }

  /**
   * Returns first non-undefined argument or the last one which is the default fallback value
   *
   * @param params
   * @returns {*|null}
   */
  prop(...params) {
    if (params.length <= 1) {
      // eslint-disable-next-line no-console
      console.log('Filter > prop method expects at least two arguments');
      return null;
    }

    if (params[params.length - 1] === undefined) {
      // eslint-disable-next-line no-console
      console.log('Filter > prop method expects the last argument not to be undefined');
      return null;
    }

    const result = params.find(o => o !== undefined);
    return result !== undefined ? result : null;
  }

  toJSON() {
    return {
      uuid: this._uuid,
      id: this._id,
      value: this._value,
      title: this._title,
      label: this._label,
      category: this._category,
      type: this._type,
      wildcardable: this._wildcardable,
      convertible: this._convertible,
      negated: this._negated,
      fullString: this._fullString,
      suspended: this._suspended,
    };
  }

  toString() {
    return JSON.stringify(this.toJSON());
  }

  valueOf() {
    this.toJSON();
  }

  /* Prop Getters */
  get id() {
    return this._id;
  }

  get uuid() {
    return this._uuid;
  }

  get value() {
    return this._value;
  }

  get title() {
    return this._title;
  }

  get label() {
    return `${this._title || this.id}: ${this._schema?.format?.(this._value) || this._value}`;
  }

  get category() {
    return this._category;
  }

  get type() {
    return this._type;
  }

  get icon() {
    return this._icon;
  }

  get negated() {
    return this._negated;
  }

  get negatable() {
    return !!this._negatable;
  }

  get fullString() {
    return !!this._fullString;
  }

  get wildcardable() {
    return !!this._wildcardable;
  }

  get convertible() {
    return !!this._convertible;
  }

  get suspended() {
    return !!this._suspended;
  }

  get schema() {
    return this._schema;
  }

  /* Custom Getters */
  get displayValue() {
    return this._schema?.format ? this._schema?.format?.(this.value) : this.value;
  }

  get convertTo() {
    return this._convertible || null;
  }

  /* Prop Setters */
  set value(value) {
    this._value = value;
    this.store();
  }

  set negated(value) {
    this.hookOnNegate();
    this._negated = !!value;
    this.store();
  }

  set fullString(value) {
    this._fullString = !!value;
    this.store();
  }

  set suspended(value) {
    this._suspended = !!value;
    this.store();
  }

  /* Actions */
  hookOnNegate() {
    if (this._schema?.onNegate) {
      const { id } = this._schema.onNegate();
      this._schema = this.findSchema(id);
      this._id = id;
    }
  }

  negate(value) {
    this.hookOnNegate();
    this._negated = value;
  }

  convert() {
    if (this.convertible) {
      const filterSchema = FiltersList.find(f => f.id === this.convertTo);
      this._id = this.convertTo;
      this._title = filterSchema?.title;
      this._label = `${filterSchema?.title}: ${filterSchema?.format?.(this._value) || this._value}`;
      this._category = filterSchema?.category;
      this._type = filterSchema?.type;

      this._convertible = this.prop(filterSchema?.convertible, false);
      this._icon = filterSchema?.icon;
      this._schema = filterSchema;
    }
    this.store();
  }

  store() {
    try {
      const storedFilters = JSON.parse(localStorage.getItem('ids_filters'));
      localStorage.setItem('ids_filters', JSON.stringify(storedFilters.map(f => (f.uuid === this._uuid ? this.toJSON() : f))));
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('Error trying to update the local stored filters');
    }
  }
}
