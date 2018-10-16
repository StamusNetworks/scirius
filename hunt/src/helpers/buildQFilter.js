export function buildQFilter(filters, system_settings) {
    var qfilter = [];
    for (var i=0; i < filters.length; i++) {
        var f_prefix = '';
        var f_suffix = '.raw';
        if (system_settings) {
            f_suffix = '.' + system_settings['es_keyword'];
        }

        if (filters[i].negated) {
            f_prefix = 'NOT ';
        }
        if (filters[i].id === 'probe') {
            qfilter.push(f_prefix + 'host.raw:' + filters[i].value);
            continue;
        } else if (filters[i].id === 'sprobe') {
            qfilter.push(f_prefix + 'host.raw:' + filters[i].value.id);
            continue;
        }
        else if (filters[i].id === 'alert.signature_id') {
            qfilter.push(f_prefix + 'alert.signature_id:' + filters[i].value);
            continue;
        }
        else if (filters[i].id === 'alert.tag') {
            var tag_filters = [];
            if (filters[i].value['untagged'] === true) {
                tag_filters.push('(NOT alert.tag:*)');
            }
            if (filters[i].value['informational'] === true) {
                tag_filters.push('alert.tag:"informational"');
            }
            if (filters[i].value['relevant'] === true) {
                tag_filters.push('alert.tag:"relevant"');
            }
            if (tag_filters.length === 0) {
                qfilter.push('alert.tag:"undefined"');
            } else if (tag_filters.length < 3) {
                qfilter.push("(" + tag_filters.join(" OR ") + ")");
            }
            continue;
        }
        else if (filters[i].id === 'msg') {
            qfilter.push(f_prefix + 'alert.signature:"' + filters[i].value + '"');
            continue;
        }
        else if ((filters[i].id === 'hits_min') || (filters[i].id === 'hits_max')) {
            continue;
        }
        else if (typeof filters[i].value === 'string') {
            qfilter.push(f_prefix + filters[i].id + f_suffix + ':"' + encodeURIComponent(filters[i].value) + '"');
            continue;
        }
        else {
            qfilter.push(f_prefix + filters[i].id + ':' + filters[i].value);
            continue;
        }
    }
    if (qfilter.length === 0) {
        return null;
    }
    return qfilter.join(" AND ");
}