const path = require('path');
entry: './server.js',
module.exports = {
  entry: './src/index.js',  // Adjust this path to your entry file
  output: {
    filename: 'bundle.js',   // The output bundle file name
    path: path.resolve(__dirname, 'dist'), // Output directory
  },
  module: {
    rules: [
      {
        test: /\.js$/,  // Transpile JavaScript files
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
        },
      },
    ],
  },
  mode: 'development', // Change to 'production' for production builds
};
