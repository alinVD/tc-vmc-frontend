
module.exports = {
    entry: "./src/index.ts",
    output: {
        filename: "dist/vm-comm.js",
        libraryTarget: "umd",
        library: "vmc"
    },
    resolve: {
        extensions: ['.ts', '.js']
    },
    module: {
        rules: [{
            test: /\.tsx?$/,
            exclude: /node_modules/,
            loader: "ts-loader"
        }]
    }
};