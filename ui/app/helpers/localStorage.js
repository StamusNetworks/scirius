import notify from 'ui/helpers/notify';

export const getFromLocalStorage = key => {
  try {
    const value = localStorage.getItem(key);
    return JSON.parse(value);
  } catch (e) {
    notify('Error getting from local storage', e);
    return null;
  }
};

export const saveToLocalStorage = (key, value) => {
  try {
    const stringified = JSON.stringify(value);
    localStorage.setItem(key, stringified);
  } catch (e) {
    notify('Error saving to local storage', e);
  }
};
