/**
 * Converts CamelCase string to camel-case by removing the preceding dash
 *
 * @param value
 */

export default function (value) {
  return value.replace(/[A-Z]/g, (match, offset) => (offset > 0 ? '-' : '') + match.toLowerCase());
}
