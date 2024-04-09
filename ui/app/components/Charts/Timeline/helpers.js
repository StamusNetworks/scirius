import { keyColors } from '../config';

export const getTimelineData = res => {
  // Server response is an object with keys: from_date, interval, and then a bunch of other keys which contain
  // the actual data inside entries. We want to transform this into a format that recharts can use.

  // Get the keys which contain the actual data
  const dataKeys = Object.keys(res).filter(key => !['from_date', 'to_date', 'interval'].includes(key));

  // Create a Record which will use timestamps as keys and contain the counts of each dataKey
  const ticks = {};

  // Populate the ticks object with the counts of each dataKey
  dataKeys.forEach(key => {
    res[key]?.entries?.forEach(({ time, count }) => {
      if (!ticks[time]) {
        ticks[time] = { [key]: count };
      } else {
        ticks[time][key] = count;
      }
    });
  });

  // Transform Record into an array of objects
  const data = Object.entries(ticks)
    .map(([time, counts]) => ({ time: parseInt(time, 10), ...counts }))
    .sort((a, b) => a.time - b.time);

  // Configure keys as props for recharts Bar component
  const keys = dataKeys.map(key => ({
    dataKey: key,
    fill: keyColors[key] || keyColors.default,
  }));

  return {
    keys,
    data,
    dates: {
      from: parseInt(res.from_date, 10),
      interval: parseInt(res.interval, 10),
    },
  };
};
