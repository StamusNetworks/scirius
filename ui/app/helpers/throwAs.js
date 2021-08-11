export const throwAs = (type, content) => {
  const methods = ['debug', 'error', 'info', 'log', 'warn'];
  const method = methods.indexOf(type) > -1 ? type : 'log';
  // eslint-disable-next-line no-console
  console[method](content);
};
