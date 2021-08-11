export const parseObjectToUrl = (obj, prefix) => {
  const str = [];
  let p;
  // eslint-disable-next-line no-restricted-syntax
  for (p in obj) {
    // eslint-disable-next-line no-prototype-builtins
    if (obj.hasOwnProperty(p)) {
      const k = prefix ? `${prefix}[${p}]` : p;
      const v = obj[p];
      str.push(v !== null && typeof v === 'object' ? parseObjectToUrl(v, k) : `${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
  }
  return str.join('&');
};
