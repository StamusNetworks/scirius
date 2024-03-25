import { StorageEnum } from 'ui/maps/StorageEnum';

export const isBooted = () => sessionStorage.getItem(StorageEnum.BOOT) || false;
export const setBooted = value => sessionStorage.setItem(StorageEnum.BOOT, value);
