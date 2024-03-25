import CommonStore from './CommonStore';
import EsStore from './EsStore';
import HistoryStore from './HistoryStore';

class RootStore {
  commonStore = null;

  historyStore = null;

  esStore = null;

  constructor() {
    this.commonStore = new CommonStore(this);
    this.historyStore = new HistoryStore(this);
    this.esStore = new EsStore(this);
  }
}

export default RootStore;
