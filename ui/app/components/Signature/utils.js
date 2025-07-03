export const getRuleData = rule => ({
  generalData: getSignatureGeneralData(rule),
  engines: getEnginesData(rule.analysis),
  metadata: getSignatureMetadata(rule),
  references: getSignatureReferences(rule.content),
});

const getSignatureGeneralData = rule => {
  const { originIp, originPort, destinationIp, destinationPort } = parseRuleContent(rule.content);
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
      value: formatString(originIp),
    },
    originPort: {
      label: 'Origin Port',
      value: formatString(originPort),
    },
    destinationIp: {
      label: 'Destination IP',
      value: formatString(destinationIp),
    },
    destinationPort: {
      label: 'Destination Port',
      value: formatString(destinationPort),
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

const getEnginesData = analysis => {
  const { engines, lists } = analysis;
  const { payload, packet } = lists;
  const engineBlocks =
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
  if (payload) {
    engineBlocks.push({
      name: 'Payload',
      matches: payload.matches?.map(match => ({
        label: match.name,
        value: match.name === 'byte_test' ? match[match.name]?.nbytes : decodeUnicodeEscapeSequence(match[match.name]?.pattern || ''),
        tags: getMatchTags(match),
      })),
    });
  }
  if (packet) {
    engineBlocks.push({
      name: 'Packet',
      matches: packet.matches?.map(match => ({
        label: match.name,
        value: '',
        tags: getMatchTags(match),
      })),
    });
  }
  return engineBlocks;
};

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
      .map(([label, value]) => ({
        label: label
          .split('_')
          .join(' ')
          .replace(/Signature/i, 'Detection method'),
        value: formatReference(value, label),
      }))
      .filter(({ label }) => label !== 'created at' && label !== 'updated at') || [];

  return [...metadata, { label: 'created at', value: rule.created || 'unknown' }, { label: 'updated at', value: rule.updated || 'unknown' }];
};

const formatReference = (value, label) => {
  const trimmedValue = value.trim();
  const cleanValue = trimmedValue.endsWith(';)') ? trimmedValue.slice(0, -2) : trimmedValue;
  if (value.startsWith('http://')) return cleanValue;
  if (value.startsWith('https://')) return cleanValue;
  if (label.toLowerCase() === 'url') return `https://${cleanValue}`;
  return cleanValue;
};

const getSignatureReferences = raw =>
  raw
    .split('; ')
    .slice(1)
    .filter(data => data.startsWith('reference:'))
    .map(data => data.slice(10))
    .map(data => data.split(','))
    .map(([label, value]) => ({ label, value: formatReference(value, label) }));

export function decodeUnicodeEscapeSequence(str) {
  return str.replace(/\\u[\dA-F]{4}/gi, function (match) {
    return String.fromCharCode(parseInt(match.replace(/\\u/g, ''), 16));
  });
}

const fallback = {
  originIp: 'unknown',
  originPort: 'unknown',
  destinationIp: 'unknown',
  destinationPort: 'unknown',
};

const parseRuleContent = content => {
  // Find the rule header section (before the first parenthesis)
  const headerEnd = content.indexOf('(');
  if (headerEnd === -1) return fallback;

  const header = content.substring(0, headerEnd).trim();
  const tokens = tokenizeHeader(header);

  // Snort rule format: alert <protocol> <source_ip> <source_port> -> <destination_ip> <destination_port>
  // We need to find the arrow (->) to separate source and destination
  const arrowIndex = tokens.findIndex(token => token === '->' || token === '=>' || token === '<>');
  if (arrowIndex === -1 || arrowIndex < 3) return fallback;

  // Extract source IP and port (before the arrow)
  const sourceIp = tokens[arrowIndex - 2];
  const sourcePort = tokens[arrowIndex - 1];

  // Extract destination IP and port (after the arrow)
  const destinationIp = tokens[arrowIndex + 1];
  const destinationPort = tokens[arrowIndex + 2];

  return {
    originIp: sourceIp || fallback.originIp,
    originPort: sourcePort || fallback.originPort,
    destinationIp: destinationIp || fallback.destinationIp,
    destinationPort: destinationPort || fallback.destinationPort,
  };
};

const tokenizeHeader = header => {
  const tokens = [];
  let currentToken = '';
  let bracketDepth = 0;
  let i = 0;

  while (i < header.length) {
    const char = header[i];

    // Check for negation followed by bracket
    if (char === '!' && i + 1 < header.length && header[i + 1] === '[' && bracketDepth === 0 && currentToken === '') {
      // Start a new token with negation
      currentToken = '![';
      bracketDepth = 1;
      i += 2; // Skip both ! and [
      /* eslint-disable-next-line no-continue */
      continue;
    }

    if (char === '[') {
      if (bracketDepth === 0) {
        // Start of a new bracket group
        if (currentToken.trim()) {
          tokens.push(currentToken.trim());
          currentToken = '';
        }
        currentToken = '[';
        bracketDepth = 1;
      } else {
        // Nested bracket
        currentToken += char;
        bracketDepth += 1;
      }
    } else if (char === ']') {
      bracketDepth -= 1;
      currentToken += char;
      if (bracketDepth === 0) {
        // End of bracket group
        tokens.push(currentToken);
        currentToken = '';
      }
    } else if (char === ' ' && bracketDepth === 0) {
      // Space outside brackets - end of token
      if (currentToken.trim()) {
        tokens.push(currentToken.trim());
        currentToken = '';
      }
    } else {
      // Add character to current token
      currentToken += char;
    }
    i += 1;
  }
  // Add any remaining token
  if (currentToken.trim()) {
    tokens.push(currentToken.trim());
  }
  return tokens.filter(token => token.length > 0);
};

function trimOuterBrackets(string) {
  const start = string.indexOf('[');
  const end = string.lastIndexOf(']');
  if (start !== 0 || end === -1) return string;
  return string.slice(start + 1, end);
}

function addSpaceAfterComma(string) {
  return string.replaceAll(',', ', ');
}

function formatString(string) {
  return trimOuterBrackets(addSpaceAfterComma(string));
}
