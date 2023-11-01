import { FilterCategory, FiltersList, FilterType } from 'ui/maps/Filters';

export default class Filter {
  #_filter = null;

  /**
   * Filter default properties
   * @type {{negated: boolean, fullString: boolean, label: null, title: null, category: string, type: string, value: null, id: null}}
   */
  #_defaults = {
    /* Filter id. Example: alert.severity */
    id: null,
    /* Filter raw value. Example: 1 */
    value: null,
    /* Filter title. Example: Severity */
    title: null,
    /* Filter label in filter bar. Example: Severity: Critical */
    label: null,
    /* Filter category. Example: event | host */
    category: FilterCategory.event,
    /* Filter type: IP | PORT | MITRE | USERNAME | HOSTNAME | ROLE | GENERIC */
    type: FilterType.GENERIC,
    /* Filter mode: including or excluding. Example: true | false */
    negated: false,
    /* Filter mode: exact match. Example: true | false */
    fullString: false,
    /* Filter temporarily suspended */
    suspended: false,
  };

  constructor(filter, value, props) {
    this.#_defaults = Object.assign(this.#_defaults, props);
    this.#_filter = this.#makeFilter(filter, value, props);
    return this;
  }

  valueOf() {
    return this.#_filter;
  }

  toString() {
    return JSON.stringify(this.#_filter);
  }

  /**
   * Returns first non undefined argument or the last one which is the default fallback value
   *
   * @param params
   * @returns {*|null}
   */
  #prop(...params) {
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

  #makeFilter(filterKey, value, props) {
    const filterSchema = FiltersList.find(f => f.id === filterKey);
    if (filterSchema) {
      return {
        ...filterSchema,
        label: `${props?.title || filterSchema.title || filterKey}: ${filterSchema.format?.(value) || value}`,
        value,
        fullString: this.#prop(props?.fullString, true),
        wildcardable: this.#prop(filterSchema?.wildcardable, true),
        negated: this.#prop(props?.negated, false),
        negatable: this.#prop(filterSchema?.negatable, true),
        convertible: this.#prop(filterSchema?.convertible, false),
        suspended: this.#prop(props?.suspended, false),
      };
    }
    return {
      /* default schema */
      title: props?.title || filterKey,
      id: filterKey,
      category: FilterCategory.EVENT,
      type: FilterType.GENERIC,
      /* default filter props */
      value,
      label: `${filterKey}: ${value}`,
      fullString: this.#prop(props?.fullString, true),
      wildcardable: this.#prop(props?.wildcardable, true),
      negated: this.#prop(props?.negated, false),
      negatable: this.#prop(props?.negatable, true),
      convertible: this.#prop(props?.convertible, false),
      suspended: this.#prop(props?.suspended, false),
    };
  }

  get instance() {
    return this.#_filter;
  }

  get value() {
    return this.#_filter.value;
  }

  get displayValue() {
    return this.#_filter.format ? this.#_filter.format(this.#_filter.value) : this.#_filter.value;
  }

  get id() {
    return this.#_filter.id;
  }

  get label() {
    return this.#_filter.label;
  }

  get category() {
    return this.#_filter.category;
  }

  get convertTo() {
    return this.#_filter.convertible || null;
  }

  get convertible() {
    return !!this.#_filter.convertible;
  }

  get wildcardable() {
    return !!this.#_filter.wildcardable;
  }

  get negatable() {
    return !!this.#_filter.negatable;
  }

  get negated() {
    return !!this.#_filter.negated;
  }

  get fullString() {
    return !!this.#_filter.fullString;
  }

  get suspended() {
    return !!this.#_filter.suspended;
  }

  get icon() {
    return this.#_filter.icon;
  }

  negate(value) {
    this.#_filter.negated = value || true;
    return this;
  }

  suspend(value) {
    this.#_filter.suspended = value === undefined ? !this.#_filter.suspended : value;
    return this;
  }

  setValue(v) {
    this.value = v;
    return this;
  }

  convert() {
    this.#_filter = this.#makeFilter(this.#_filter.convertible, this.value, { negated: this.#_filter.negated, fullString: this.#_filter.fullString });
    return this;
  }
}
