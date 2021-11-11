import moment from 'moment';

const getTimePoints = (startDate, granularity) => {
  const granulates = ['minutes', 'hours', 'days', 'weeks', 'months', 'years'];
  if (!granularity || (granularity && granulates.indexOf(granularity) === -1)) {
    // eslint-disable-next-line no-console
    console.error(`getTimePoints requires a valid granularity value. Used ${granularity}. Valid ones: ${granulates.join(', ')}`)
    return [];
  }
  if (!(startDate instanceof moment)) {
    // eslint-disable-next-line no-console
    console.error(`getTimePoints requires a valid startDate parameter instance of momentjs`);
  }

  const pointsCount = moment().diff(startDate, granularity);
  const singlePointPeriod = moment().diff(startDate, 'seconds') / pointsCount;

  const result = [];
  for (let i = 0; i < pointsCount; i += 1) {
    result.push(moment().subtract(singlePointPeriod * i, 'seconds').startOf(granularity).toDate())
  }
  return result.reverse();
}

export default getTimePoints;
