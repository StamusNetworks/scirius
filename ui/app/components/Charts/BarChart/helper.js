export const getInitialTicks = (from, to, interval) => {
  const ticks = {};
  for (let i = from; i <= to; i += interval) {
    ticks[i] = {};
  }
  return ticks;
};
