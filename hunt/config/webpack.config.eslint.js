// set NODE_ENV, then load webpack.config.dev to give eslint access to aliases
// defined in webpack config (see module.exports.resolve.alias in webpack.config.dev.js)
process.env.NODE_ENV = 'dev';

const webpackDev = require('./webpack.config.dev');

module.exports = webpackDev;
