import CommonStore from './CommonStore';
import HistoryStore from './HistoryStore';

class RootStore {
  commonStore = null;

  historyStore = null;

  constructor() {
    console.log('RootStore CE');
    this.commonStore = new CommonStore(this);
    this.historyStore = new HistoryStore(this);
  }
}

export default RootStore;

export const store = new RootStore();
