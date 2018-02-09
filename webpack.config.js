const path = require("path");
const ExtractTextPlugin = require("extract-text-webpack-plugin");

const extractSass = new ExtractTextPlugin({
  filename: "styles.css",
  disable: process.env.NODE_ENV === "development"
});

module.exports = {
  entry: "./npm/scirius-bundle.js",
  module: {
    loaders: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: "babel-loader",
          options: {
            presets: ["@babel/preset-env"]
          }
        }
      },
      {
        test: /\.(css|scss)$/,
        use: extractSass.extract({
          use: [
            {
              loader: "css-loader"
            },
            {
              loader: "sass-loader"
            }
          ],
          fallback: "style-loader"
        })
      },
      {
        test: /\.woff(2)?(\?v=[0-9]\.[0-9]\.[0-9])?$/,
        loader: "url-loader?limit=10000&mimetype=application/font-woff"
      },
      {
        test: /\.(ttf|otf|eot|svg)(\?v=[0-9]\.[0-9]\.[0-9])?|(jpg|gif|png)$/,
        loader: "file-loader"
      },
      {
        test: /\.svg$/,
        loader: "svg-inline-loader"
      }
    ]
  },
  plugins: [extractSass],
  output: {
    path: path.resolve(__dirname, "rules/static/dist"),
    filename: "scirius-bundle.js"
  }
};
