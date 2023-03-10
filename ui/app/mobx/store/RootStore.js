import CommonStore from './CommonStore';

class RootStore {
  commonStore = null;

  constructor() {
    this.commonStore = new CommonStore(this);
  }
}

export default RootStore;
