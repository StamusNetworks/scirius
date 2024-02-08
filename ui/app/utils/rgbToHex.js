function componentToHex(c) {
  const hex = c.toString(16);
  return hex.length === 1 ? `0${hex}` : hex;
}

export function rgbToHex(string) {
  const [r, g, b] = string.slice(4, -1).split(', ').map(Number);
  return `#${componentToHex(r)}${componentToHex(g)}${componentToHex(b)}`;
}
