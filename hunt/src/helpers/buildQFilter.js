export function buildQFilter(filters, systemSettings) {
    const qfilter = [];
    let output = '';
    let fSuffix = '.raw';

    if (systemSettings) {
        fSuffix = `.${systemSettings.es_keyword}`;
    }

    for (let i = 0; i < filters.length; i += 1) {
        if (filters[i].id.substring(0, 8) !== 'host_id.' && filters[i].id !== 'hits_min' && filters[i].id !== 'hits_max') {
            let fPrefix = '';

            if (filters[i].negated) {
                fPrefix = 'NOT ';
            }

            if (filters[i].id === 'probe') {
                qfilter.push(`${fPrefix}host.raw:${filters[i].value}`);
            } else if (filters[i].id === 'sprobe') {
                qfilter.push(`${fPrefix}host.raw:${filters[i].value.id}`);
            } else if (filters[i].id === 'alert.signature_id') {
                qfilter.push(`${fPrefix}alert.signature_id:${filters[i].value}`);
            } else if (filters[i].id === 'ip') {
                qfilter.push(`"${filters[i].value}"`);
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
            } else if (filters[i].id === 'msg') {
                qfilter.push(`${fPrefix}alert.signature:"${filters[i].value}"`);
            } else if (filters[i].id === 'alert.category' && filters[i].value === 'Unknown') {
                qfilter.push(`${fPrefix}alert.category${fSuffix}:""`);
            } else if (filters[i].id === 'not_in_msg') {
                qfilter.push(`${fPrefix}NOT alert.signature:"${filters[i].value}"`);
            } else if (typeof filters[i].value === 'string') {
                const value = filters[i].value.replace(/\\/g, '\\\\');
                qfilter.push(`${fPrefix}${filters[i].id}${fSuffix}:"${encodeURIComponent(value)}"`);
            } else {
                qfilter.push(`${fPrefix}${filters[i].id}:${filters[i].value}`);
            }
        }
    }

    if (qfilter.length === 0) {
        return null;
    }

    output += (qfilter.length) ? `&qfilter=${qfilter.join(' AND ')}` : '';
    return (output.length) ? output : null;
}
