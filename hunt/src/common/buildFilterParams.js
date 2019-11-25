export function buildFilterParams(filterParams) {
    const fromDate = `from_date=${filterParams.fromDate}`;
    const toDate = `&to_date=${filterParams.toDate}`;
    return `${fromDate}${toDate}`;
}
