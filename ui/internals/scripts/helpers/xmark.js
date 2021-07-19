const chalk = require('chalk');

/**
 * Adds mark cross symbol
 */
function addXMark(callback) {
  process.stdout.write(chalk.red(' ✘')); /* ignore_utf8_check: 10008 */
  if (callback) callback();
}

module.exports = addXMark;
