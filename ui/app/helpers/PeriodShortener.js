import moment from 'moment';

// seconds in labels
export const USER_PERIODS = {
  3600000: '1h',
  21600000: '6h',
  86400000: '24h',
  172800000: '2d',
  604800000: '7d',
  2592000000: '30d',
  31540000000: '1y',
  all: 'All',
};

const getSecond = (fromDate, toDate) => [fromDate.format('ss'), toDate.format('ss')];
const getMinute = (fromDate, toDate) => [fromDate.format('mm'), toDate.format('mm')];
const getHour = (fromDate, toDate) => [fromDate.format('HH'), toDate.format('HH')];
const getDay = (fromDate, toDate) =>
  fromDate.year() === toDate.year() && fromDate.month() === toDate.month() && fromDate.date() === toDate.date()
    ? [fromDate.format('D')]
    : [fromDate.format('D'), toDate.format('D')];
const getMonth = (fromDate, toDate) =>
  fromDate.year() === toDate.year() && fromDate.month() === toDate.month()
    ? [fromDate.format('MMM')]
    : [fromDate.format('MMM'), toDate.format('MMM')];
const getYear = (fromDate, toDate) =>
  fromDate.year() === toDate.year() ? [fromDate.format('YYYY')] : [fromDate.format('YYYY'), toDate.format('YYYY')];

const omitZeroes = (hour, minute, second) =>
  hour.filter(v => v !== '00').length === 0 && minute.filter(v => v !== '00').length === 0 && second.filter(v => v !== '00').length === 0;
const dayName = n => `${n}${['st', 'nd', 'rd'][((((parseInt(n, 10) + 90) % 100) - 10) % 10) - 1] || 'th'}`;

export const periodShortener = (fromDate, toDate, duration) => {
  const from = moment(fromDate);
  const to = moment(toDate);

  let resultFinal = '';
  if (duration !== null) {
    const period = USER_PERIODS[duration];
    resultFinal = period !== USER_PERIODS.all ? `Last ${period}` : `${period}`;
  } else {
    const year = getYear(from, to);
    const month = getMonth(from, to);
    const day = getDay(from, to);
    const hour = getHour(from, to);
    const minute = getMinute(from, to);
    const second = getSecond(from, to);
    if (year.length === 1) {
      [resultFinal] = year;
      if (month.length === 1) {
        resultFinal = `${resultFinal}-${month[0]}`;
        if (day.length === 1) {
          resultFinal = `${resultFinal}-${dayName(day[0])}`;
          if (omitZeroes(hour, minute, second)) {
            resultFinal = `${resultFinal} ${hour[0]}:${minute[0]}:${second[0]}`;
          } else {
            resultFinal = `${resultFinal} (${hour[0]}:${minute[0]}:${second[0]} to ${hour[1]}:${minute[1]}:${second[1]})`;
          }
        } else {
          resultFinal = omitZeroes(hour, minute, second)
            ? `${resultFinal} (${dayName(day[0])} to ${dayName(day[1])})`
            : `${resultFinal} (${dayName(day[0])} ${hour[0]}:${minute[0]}:${second[0]} to ${dayName(day[1])} ${hour[1]}:${minute[1]}:${second[1]})`;
        }
      } else {
        resultFinal = omitZeroes(hour, minute, second)
          ? `${resultFinal} (${month[0]} ${dayName(day[0])} to ${month[1]} ${dayName(day[1])})`
          : `${resultFinal} (${month[0]} ${dayName(day[0])} ${hour[0]}:${minute[0]}:${second[0]} to ${month[1]} ${dayName(day[1])} ${hour[1]}:${
              minute[1]
            }:${second[1]})`;
      }
    } else {
      resultFinal = omitZeroes(hour, minute, second)
        ? `${year[0]}-${month[0]}-${dayName(day[0])} to ${year[1]}-${month[1]}-${dayName(day[1])}`
        : `${year[0]}-${month[0]}-${dayName(day[0])} ${hour[0]}:${minute[0]}:${second[0]} - ${year[1]}-${month[1]}-${dayName(day[1])} ${hour[1]}:${
            minute[1]
          }:${second[1]}`;
    }
  }

  return resultFinal;
};
