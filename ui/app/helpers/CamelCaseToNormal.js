/**
 * Converts CamelCase string Camel Case with spaces
 *
 * @param value
 */

export default function (value) {
  return value
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, function(str){ return str.toUpperCase(); })
}
