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

  #makeFilter(filterKey, value, props) {
    const filterSchema = FiltersList.find(f => f.id === filterKey);
    if (filterSchema) {
      return {
        ...filterSchema,
        label: `${props?.title || filterSchema.title || filterKey}: ${filterSchema.format?.(value) || value}`,
        value,
        negated: props?.negated || false,
        fullString: props?.fullString !== undefined ? props.fullString : true,
        convertible: filterSchema?.convertible !== undefined ? filterSchema?.convertible : false,
        suspended: props?.suspended !== undefined ? props.suspended : false,
      };
    }
    return {
      /* default schema */
      title: props?.title || filterKey,
      id: filterKey,
      category: FilterCategory.event,
      type: FilterType.GENERIC,
      /* default filter props */
      value,
      label: `${filterKey}: ${value}`,
      negated: props?.negated || false,
      fullString: props?.fullString !== undefined ? props?.fullString : false,
      convertible: filterSchema?.convertible !== undefined ? filterSchema?.convertible : false,
      suspended: props?.suspended !== undefined ? props?.suspended : false,
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

  get convertible() {
    return !!this.#_filter.convertible;
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
