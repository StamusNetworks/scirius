import store from 'store';

const timespan = store.get('timespan') || { fromDate: Date.now() - (24 * 3600 * 1000), toDate: Date.now(), duration: 24 * 3600 * 1000 };
export const defaultFilterParams = {
    hash: '',
    duration: timespan.duration,
    fromDate: timespan.fromDate,
    toDate: timespan.toDate,
};
