export function buildFilterParams(filterParams) {
    const fromDate = (filterParams.duration > 0) ? `from_date=${(Date.now() - parseInt(filterParams.duration, 10))}` : `from_date=${filterParams.fromDate}`;
    const toDate = (filterParams.duration > 0) ? `&to_date=${Date.now()}` : `&to_date=${filterParams.toDate}`;
    return `${fromDate}${toDate}`;
}
