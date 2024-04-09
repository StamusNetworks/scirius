import IP_FIELDS from 'ui/config/ipFields';

export function esEscape(str) {
  // https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html#_reserved_characters
  // Can't search on < >
  const result = str.replace(/[<>]/g, '');

  // Escape other reserved characters
  return result.replace(/[=+\-&|!(){}[\]^"~:\\/]/g, c => `\\${c}`);
}

export function buildQFilter(activeFilters, systemSettings, returnType = 'legacy') {
  const qfilter = [];
  let fSuffix = '.raw';

  if (systemSettings) {
    fSuffix = `.${systemSettings.es_keyword}`;
  }

  const filters = activeFilters.filter(f => f.suspended !== true);
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
      } else if (filters[i].id === 'stamus.kill_chain') {
        qfilter.push(`${fPrefix}stamus.kill_chain.raw:"${filters[i].value.toLowerCase().replaceAll(' ', '_')}"`);
      } else if (filters[i].id === 'alert.signature_id') {
        qfilter.push(`${fPrefix}alert.signature_id:${filters[i].value}`);
      } else if (filters[i].id === 'ip') {
        qfilter.push(`${fPrefix}(src_ip:"${filters[i].value}" OR dest_ip:"${filters[i].value}")`);
      } else if (IP_FIELDS.includes(filters[i].id)) {
        qfilter.push(`${fPrefix}${filters[i].id}:"${filters[i].value}"`);
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
        if (filters[i].value.untagged === false && filters[i].value.informational === false && filters[i].value.relevant === false) {
          tagFilters.push('alert.tag:"none"');
        }
        if (tagFilters.length !== 0) {
          qfilter.push(`(${tagFilters.join(' OR ')})`);
        }
      } else if (filters[i].id === 'msg' || filters[i].id === 'not_in_msg') {
        // continue
      } else if (filters[i].id === 'content' || filters[i].id === 'not_in_content') {
        // continue
      } else if (filters[i].id === 'es_filter') {
        qfilter.push(`${fPrefix}(${filters[i].value})`);
      } else if (filters[i].id === 'port') {
        qfilter.push(`${fPrefix}(src_port:${filters[i].value} OR dest_port:${filters[i].value})`);
      } else if (filters[i].id === 'alert.category' && filters[i].value === 'Unknown') {
        qfilter.push(`${fPrefix}alert.category${fSuffix}:""`);
      } else if (typeof filters[i].value === 'string') {
        if (filters[i].fullString) {
          const value = filters[i].value.toString().replace(/\\/g, '\\\\').replace(/"/g, '\\"');
          qfilter.push(`${fPrefix}${filters[i].id}${fSuffix}:"${value}"`);
        } else {
          const value = esEscape(filters[i].value.toString());
          qfilter.push(`${fPrefix}${filters[i].id}:${value}`);
        }
      } else {
        qfilter.push(`${fPrefix}${filters[i].id}:${filters[i].value}`);
      }
    }
  }
  if (returnType === 'object') {
    return qfilter.length ? { qfilter: qfilter.join(' AND ') } : {};
  }
  return qfilter.length ? `&qfilter=${encodeURIComponent(qfilter.join(' AND '))}` : '';
}
