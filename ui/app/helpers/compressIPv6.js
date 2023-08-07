const compressIPv6 = ip => {
  // First remove the leading 0s of the octets. If it's '0000', replace with '0'
  let output = ip
    .split(':')
    .map(terms => terms.replace(/\b0+/g, '') || '0')
    .join(':');

  // Then search for all occurrences of continuous '0' octets
  const zeros = [...output.matchAll(/\b:?(?:0+:?){2,}/g)];

  // If there are occurrences, see which is the longest one and replace it with '::'
  if (zeros.length > 0) {
    let max = '';
    zeros.forEach(item => {
      if (item[0].replaceAll(':', '').length > max.replaceAll(':', '').length) {
        max = item?.[0];
      }
    });
    output = output.replace(max, '::');
  }
  return output;
};

export default compressIPv6;
