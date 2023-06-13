import { makeAutoObservable } from 'mobx';
import qs from 'qs';

import { api } from 'ui/mobx/api';
import endpoints from 'ui/config/endpoints';

// Es stands for Elasticsearch
// this is where we house all the requests `/rest/rules/es/*`
class EsStore {
  rootStore;

  fieldStats = [];

  timeline = {};

  alertsCount = {};

  alertsTail = {};

  constructor(rootStore) {
    this.rootStore = rootStore;
    makeAutoObservable(this, {
      rootStore: false,
    });
  }

  async fetchFieldStats(field, pageSize, qfilter) {
    // additional query params should be passed in the object after the url
    const response = await api.get(`${endpoints.FIELD_STATS.url}`, {
      field,
      page_size: pageSize,
      qfilter: decodeURIComponent(qfilter.replace('&qfilter=', '')),
    });

    if (response.ok) {
      this.fieldStats = response.data;
    }
    return response.data;
  }

  async fetchTimeline(target, qfilter) {
    const response = await api.get(`${endpoints.TIMELINE.url}`, {
      target,
      qfilter: decodeURIComponent(qfilter.replace('&qfilter=', '')),
    });

    if (response.ok) {
      this.timeline = response.data;
    }
    return response.data;
  }

  async fetchAlertsCount(qfilter) {
    const response = await api.get(`${endpoints.ALERTS_COUNT.url}`, {
      qfilter: decodeURIComponent(qfilter.replace('&qfilter=', '')),
    });

    if (response.ok) {
      this.alertsCount = response.data;
    }
    return response.data;
  }

  async fetchAlertsTail(paginationParams, qfilter) {
    const response = await api.get(`${endpoints.ALERTS_TAIL.url}`, {
      qfilter: decodeURIComponent(qfilter.replace('&qfilter=', '')),
      ...qs.parse(paginationParams),
    });

    if (response.ok) {
      this.alertsTail = response.data;
    } else throw new Error(response.originalError);

    return response.data;
  }
}

export default EsStore;
