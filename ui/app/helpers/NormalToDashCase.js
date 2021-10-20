/**
 * Converts normal string with spaces to dash-case
 *
 * @example "Normal String Here" to "normal-string-here"
 */

export default function (value) {
  return value.replace(/\s+/g, '-').toLowerCase();
}
