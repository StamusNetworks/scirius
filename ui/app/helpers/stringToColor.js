export const stringToColor = value => {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) {
    // eslint-disable-next-line no-bitwise
    hash = value.charCodeAt(i) + ((hash << 5) - hash);
  }

  return `hsl(${hash % 360}, 85%, 55%)`;
};
