import { makeAutoObservable } from 'mobx';
import * as config from 'config/Api';
import { api } from '../api';

class HistoryStore {
  root = null;

  historyItemsList = [];

  historyItemsCount = 0;

  constructor(root) {
    this.root = root;
    makeAutoObservable(this, {
      root: false,
    });
  }

  async fetchData(stringFilters, listParams) {
    const response = await api.get(`rest/${config.HISTORY_PATH}?${listParams}${stringFilters}`);
    if (response.ok) {
      this.historyItemsList = response.data.results;
      this.historyItemsCount = response.data.count;
    }
    return response;
  }
}

export default HistoryStore;
