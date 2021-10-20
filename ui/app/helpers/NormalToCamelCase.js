/**
 * Converts normal string with spaces to camelCase
 *
 * @example "normal string here" to "normalStringHere"
 */

export default function (value) {
  return value
    .replace(/\s(.)/g, function($1) { return $1.toUpperCase(); })
    .replace(/\s/g, '')
    .replace(/^(.)/, function($1) { return $1.toLowerCase(); });
}
