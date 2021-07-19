const chalk = require('chalk');

/**
 * Adds mark check symbol
 */
function addCheckMark(callback) {
  process.stdout.write(chalk.green(' ✓')); /* ignore_utf8_check: 10003 */
  if (callback) callback();
}

module.exports = addCheckMark;
