import store from 'store';
import moment from 'moment';

const storedStamp = store.get('timespan');
let timespan = null;

export const absolute = {
    from: {
        id: 0,
        value: 0,
        time: moment(),
        now: false,
    },
    to: {
        id: 0,
        value: 0,
        time: moment(),
        now: false,
    },
};

if (storedStamp) {
    if (storedStamp.duration) {
        timespan = {
            duration: storedStamp.duration,
            fromDate: Math.round(Date.now() - storedStamp.duration),
            toDate: Date.now(),
            absolute
        }
    } else {
        timespan = storedStamp;
    }

    timespan.absolute.from.time = moment(storedStamp.absolute.from.time);
    timespan.absolute.to.time = moment(storedStamp.absolute.to.time);
} else {
    timespan = {
        duration: '86400000',
        fromDate: Math.round(Date.now() - (24 * 3600 * 1000)),
        toDate: Date.now(),
        absolute,
    }
}

export const defaultFilterParams = {
    hash: '',
    ...timespan,
};
