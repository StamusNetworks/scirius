export function buildQFilter(filters, systemSettings) {
    const qfilter = [];
    for (let i = 0; i < filters.length; i += 1) {
        let fPrefix = '';
        let fSuffix = '.raw';
        if (systemSettings) {
            fSuffix = `.${systemSettings.es_keyword}`;
        }

        if (filters[i].negated) {
            fPrefix = 'NOT ';
        }
        if (filters[i].id === 'probe') {
            qfilter.push(`${fPrefix}host.raw:${filters[i].value}`);
            // eslint-disable-next-line no-continue
            continue;
        } else if (filters[i].id === 'sprobe') {
            qfilter.push(`${fPrefix}host.raw:${filters[i].value.id}`);
            // eslint-disable-next-line no-continue
            continue;
        } else if (filters[i].id === 'alert.signature_id') {
            qfilter.push(`${fPrefix}alert.signature_id:${filters[i].value}`);
            // eslint-disable-next-line no-continue
            continue;
        } else if (filters[i].id === 'alert.tag') {
            const tagFilters = [];
            if (filters[i].value.untagged === true) {
                tagFilters.push('(NOT alert.tag:*)');
            }
            if (filters[i].value.informational === true) {
                tagFilters.push('alert.tag:"informational"');
            }
            if (filters[i].value.relevant === true) {
                tagFilters.push('alert.tag:"relevant"');
            }
            if (tagFilters.length === 0) {
                qfilter.push('alert.tag:"undefined"');
            } else if (tagFilters.length < 3) {
                qfilter.push(`(${tagFilters.join(' OR ')})`);
            }
            // eslint-disable-next-line no-continue
            continue;
        } else if (filters[i].id === 'msg') {
            qfilter.push(`${fPrefix}alert.signature:"${filters[i].value}"`);
            // eslint-disable-next-line no-continue
            continue;
        } else if (filters[i].id === 'not_in_msg') {
            qfilter.push(`${fPrefix}NOT alert.signature:"${filters[i].value}"`);
            // eslint-disable-next-line no-continue
            continue;
        } else if ((filters[i].id === 'hits_min') || (filters[i].id === 'hits_max')) {
            // eslint-disable-next-line no-continue
            continue;
        } else if (typeof filters[i].value === 'string') {
            qfilter.push(`${fPrefix}${filters[i].id}${fSuffix}:"${encodeURIComponent(filters[i].value)}"`);
            // eslint-disable-next-line no-continue
            continue;
        } else {
            qfilter.push(`${fPrefix}${filters[i].id}:${filters[i].value}`);
            // eslint-disable-next-line no-continue
            continue;
        }
    }
    if (qfilter.length === 0) {
        return null;
    }
    return qfilter.join(' AND ');
}
