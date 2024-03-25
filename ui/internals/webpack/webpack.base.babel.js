/**
 * COMMON WEBPACK CONFIGURATION
 */

const path = require('path');

const webpack = require('webpack');

const { ANTD_THEME } = require('../../app/constants/antd.json');

module.exports = options => ({
  mode: options.mode,
  entry: options.entry,
  output: Object.assign(
    {
      // Compile into js/build.js
      path: path.resolve(process.cwd(), 'build'),
      publicPath: '/',
    },
    options.output,
  ), // Merge with env dependent settings
  optimization: options.optimization,
  module: {
    rules: [
      {
        test: /\.jsx?$/, // Transform all .js and .jsx files into ES5
        exclude: /node_modules/, // everything in node_modules is already ES5
        use: [
          {
            loader: 'babel-loader',
            options: {
              presets: [['@babel/preset-env', { targets: 'defaults' }], '@babel/preset-react'],
              plugins: ['babel-plugin-styled-components', ['import', { libraryName: 'antd', libraryDirectory: 'es', style: true }]],
            },
          },
        ],
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader'],
      },
      {
        test: /\.less$/,
        use: [
          'style-loader',
          'css-loader',
          {
            loader: 'less-loader',
            options: {
              lessOptions: {
                javascriptEnabled: true,
                modifyVars: ANTD_THEME,
              },
              sourceMap: true,
            },
          },
        ],
      },
      {
        test: /\.(eot|otf|ttf|woff|woff2)$/,
        use: 'file-loader',
      },
      {
        test: /\.(jpe?g|png|gif|svg)$/,
        use: [
          {
            loader: 'url-loader',
            options: {
              // images smaller than 10000 bytes/10 kB will be encoded as base64 & included in the bundle.js
              limit: 10000,
            },
          },
        ],
      },
    ],
  },
  plugins: options.plugins.concat([
    new webpack.ContextReplacementPlugin(/^\.\/locale$/, context => {
      if (!/\/moment\//.test(context.context)) return;

      Object.assign(context, {
        regExp: /^\.\/\w+/,
        request: '../../locale', // resolved relatively
      });
    }),
    // Always expose NODE_ENV to webpack, in order to use `process.env.NODE_ENV`
    // inside your code for any environment checks; Terser will automatically
    // drop any unreachable code.
    new webpack.EnvironmentPlugin({
      NODE_ENV: 'development',
    }),
    // https://stackoverflow.com/questions/68707553/uncaught-referenceerror-buffer-is-not-defined
    // Work around for Buffer is undefined:
    // https://github.com/webpack/changelog-v5/issues/10
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
    }),
  ]),
  resolve: {
    modules: ['node_modules', 'app'],
    extensions: ['.js', '.jsx', '.react.js'],
    mainFields: ['browser', 'jsnext:main', 'main'],
    alias: {
      ui: [path.resolve(__dirname, '../../app/appliance/'), path.resolve(__dirname, '../../app/')],
    },
  },
  devtool: options.devtool,
  target: 'web', // Make web variables accessible to webpack, e.g. window
  performance: options.performance || {},
});
