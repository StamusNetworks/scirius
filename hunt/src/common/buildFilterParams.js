export function buildFilterParams(filterParams) {
    const fromDate = `from_date=${filterParams.duration === null ? filterParams.fromDate : Math.round(Date.now() / 1000) - filterParams.duration}`;
    const toDate = `&to_date=${filterParams.duration === null ? filterParams.toDate : Math.round(Date.now() / 1000)}`;
    return `${fromDate}${toDate}`;
}
