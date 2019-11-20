/* eslint-disable no-confusing-arrow */
import moment from 'moment';

// seconds in labels
export const USER_PERIODS = {
    3600: '1h',
    21600: '6h',
    86400: '24h',
    172800: '2d',
    604800: '7d',
    2592000: '30d'
};

const getSecond = (fromDate, toDate) => [fromDate.format('ss'), toDate.format('ss')];
const getMinute = (fromDate, toDate) => [fromDate.format('mm'), toDate.format('mm')];
const getHour = (fromDate, toDate) => [fromDate.format('HH'), toDate.format('HH')];
const getDay = (fromDate, toDate) => (fromDate.year() === toDate.year() && fromDate.month() === toDate.month() && fromDate.date() === toDate.date()) ? [fromDate.format('D')] : [fromDate.format('D'), toDate.format('D')];
const getMonth = (fromDate, toDate) => (fromDate.year() === toDate.year() && fromDate.month() === toDate.month()) ? [fromDate.format('MMM')] : [fromDate.format('MMM'), toDate.format('MMM')];
const getYear = (fromDate, toDate) => (fromDate.year() === toDate.year()) ? [fromDate.format('YYYY')] : [fromDate.format('YYYY'), toDate.format('YYYY')];

const omitZeroes = (hour, minute, second) => (hour.filter((v) => v !== '00').length === 0 && minute.filter((v) => v !== '00').length === 0 && second.filter((v) => v !== '00').length === 0);
const dayName = (d) => {
    switch (parseInt(d, 10) % 10) {
        case 1:
            return `${d}st`;
        case 2:
            return `${d}nd`;
        case 3:
            return `${d}rd`;
        default:
            return `${d}th`;
    }
}

export const periodShortener = (fromDate, toDate, duration) => {
    const from = moment(fromDate);
    const to = moment(toDate);

    let resultFinal = '';
    if (duration !== null) {
        resultFinal = `Last ${USER_PERIODS[duration]}`;
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
                    resultFinal = omitZeroes(hour, minute, second) ? `${resultFinal} (${dayName(day[0])} to ${dayName(day[1])})` : `${resultFinal} (${dayName(day[0])} ${hour[0]}:${minute[0]}:${second[0]} to ${dayName(day[1])} ${hour[1]}:${minute[1]}:${second[1]})`;
                }
            } else {
                resultFinal = omitZeroes(hour, minute, second) ? `${resultFinal} (${month[0]} ${dayName(day[0])} to ${month[1]} ${dayName(day[1])})` : `${resultFinal} (${month[0]} ${dayName(day[0])} ${hour[0]}:${minute[0]}:${second[0]} to ${month[1]} ${dayName(day[1])} ${hour[1]}:${minute[1]}:${second[1]})`;
            }
        } else {
            resultFinal = omitZeroes(hour, minute, second) ? `${year[0]}-${month[0]}-${dayName(day[0])} to ${year[1]}-${month[1]}-${dayName(day[1])}` : `${year[0]}-${month[0]}-${dayName(day[0])} ${hour[0]}:${minute[0]}:${second[0]} - ${year[1]}-${month[1]}-${dayName(day[1])} ${hour[1]}:${minute[1]}:${second[1]}`;
        }
    }

    return resultFinal;
}
