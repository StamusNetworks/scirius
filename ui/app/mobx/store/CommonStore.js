import { makeAutoObservable } from 'mobx';

class CommonStore {
  root = null;

  constructor(root) {
    this.root = root;
    makeAutoObservable(this, {
      root: false,
    });
  }
}

export default CommonStore;
