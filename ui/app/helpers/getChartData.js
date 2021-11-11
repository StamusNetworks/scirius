import moment from 'moment';

const getChartData = (points, data) => {
  const result = [];
  [...points, moment()].reduce((prev, curr) => {
      result.push(data.filter(d => moment(d.date).isBetween(prev, curr)).map(v => v.value).reduce((a, b) => a + b, 0));
      return curr;
  });
  return result;
}

export default getChartData;
