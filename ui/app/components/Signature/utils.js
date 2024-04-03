export const getRuleData = rule => ({
  generalData: getSignatureGeneralData(rule),
  engines: getEnginesData(rule.analysis.engines),
  lists: getEnginesData(Object.entries(rule.analysis.lists).map(([name, data]) => ({ ...data, name })) || []),
  metadata: getSignatureMetadata(rule),
  references: getSignatureReferences(rule.content),
});

const getSignatureGeneralData = rule => {
  const ruleArray = rule.content.split(' ');
  let destination = 'unknown';
  if (rule.analysis.flags?.includes('toclient')) destination = 'client';
  if (rule.analysis.flags?.includes('toserver')) destination = 'server';

  let target = 'unknown';
  if (rule.analysis.flags?.includes('src_is_target')) target = 'source';
  if (rule.analysis.flags?.includes('dst_is_target')) target = 'destination';

  const rawClasstype = /(?<=classtype:).*?(?=;)/g.exec(rule.content);
  const classtype = !rawClasstype
    ? 'None'
    : rawClasstype[0]
        .split('-')
        .map(item => item[0].toUpperCase() + item.slice(1))
        .join(' ');

  return {
    originIp: {
      label: 'Origin IP',
      value: ruleArray[2],
    },
    originPort: {
      label: 'Origin Port',
      value: ruleArray[3],
    },
    destinationIp: {
      label: 'Destination IP',
      value: ruleArray[5],
    },
    destinationPort: {
      label: 'Destination Port',
      value: ruleArray[6],
    },
    protocol: {
      label: 'Protocol',
      value: rule.analysis.app_proto,
    },
    rev: {
      label: 'Revision',
      value: rule.analysis.rev,
    },
    classtype: {
      label: 'Class-Type',
      value: classtype,
    },
    destination,
    target,
  };
};

const getEnginesData = engines =>
  engines?.reduce((prev, cur) => {
    if (prev.find(obj => obj.name === cur.name)) return prev;
    const currentEngine = {
      ...cur,
      transforms: cur.transforms?.map(transform => transform.name),
      matches: cur.matches?.map(match => ({
        label: match.name,
        value: decodeUnicodeEscapeSequence(match[match.name]?.pattern || ''),
        tags: getMatchTags(match),
      })),
    };
    return [...prev, currentEngine];
  }, []) || [];

const getMatchTags = match => {
  const blacklist = ['is_mpm', 'no_double_inspect'];
  const tags = [];

  const content = match[match.name] || {};
  const keys = Object.keys(content) || [];

  if (typeof content.length !== 'undefined') tags.push(`length: ${content.length}`);
  tags.push(...keys.filter(key => content[key] === true).filter(key => !blacklist.includes(key)));

  return tags;
};

export const getEngineTagColor = tag => {
  const highlighted = ['fast_pattern'];

  if (highlighted.includes(tag)) return 'purple';

  return 'blue';
};

const getSignatureMetadata = rule => {
  const metadata =
    rule.content
      ?.split('metadata:')[1]
      ?.split(', ')
      .map(data => data.split(' '))
      .map(([label, value]) => ({ label: label.split('_').join(' '), value }))
      .filter(({ label }) => label !== 'created at' && label !== 'updated at') || [];

  return [...metadata, { label: 'created at', value: rule.created || 'unknown' }, { label: 'updated at', value: rule.updated || 'unknown' }];
};

const getSignatureReferences = raw =>
  raw
    .split('; ')
    .slice(1)
    .filter(data => data.startsWith('reference:'))
    .map(data => data.slice(10))
    .map(data => data.split(','))
    .map(([label, value]) => ({ label, value }));

export function decodeUnicodeEscapeSequence(str) {
  return str.replace(/\\u[\dA-F]{4}/gi, function (match) {
    return String.fromCharCode(parseInt(match.replace(/\\u/g, ''), 16));
  });
}
