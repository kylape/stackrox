const path = require('path');
const { ConsoleRemotePlugin } = require('@openshift-console/dynamic-plugin-sdk-webpack');
const CopyWebpackPlugin = require('copy-webpack-plugin');

const isProd = process.env.NODE_ENV === 'production';

const config = {
    mode: isProd ? 'production' : 'development',
    // No regular entry points needed. All plugin related scripts are generated via ConsoleRemotePlugin.
    entry: {},
    context: path.resolve(__dirname, 'src'),
    output: {
        path: path.resolve(__dirname, 'build', 'static', 'ocp-plugin'),
        filename: isProd ? '[name]-bundle-[hash].min.js' : '[name]-bundle.js',
        chunkFilename: isProd ? '[name]-chunk-[chunkhash].min.js' : '[name]-chunk.js',
    },
    resolve: {
        extensions: ['.ts', '.tsx', '.js', '.jsx'],
        alias: {
            Containers: path.resolve(__dirname, 'src/Containers'),
            Components: path.resolve(__dirname, 'src/Components'),
            services: path.resolve(__dirname, 'src/services'),
            utils: path.resolve(__dirname, 'src/utils'),
            hooks: path.resolve(__dirname, 'src/hooks'),
            types: path.resolve(__dirname, 'src/types'),
            constants: path.resolve(__dirname, 'src/constants'),
            queries: path.resolve(__dirname, 'src/queries'),
            reducers: path.resolve(__dirname, 'src/reducers'),
            sagas: path.resolve(__dirname, 'src/sagas'),
            messages: path.resolve(__dirname, 'src/messages'),
            mockData: path.resolve(__dirname, 'src/mockData'),
            sorters: path.resolve(__dirname, 'src/sorters'),
            'test-utils': path.resolve(__dirname, 'src/test-utils'),
            images: path.resolve(__dirname, 'src/images'),
            css: path.resolve(__dirname, 'src/css'),
        },
    },
    module: {
        rules: [
            {
                test: /\.(jsx?|tsx?)$/,
                exclude: /\/node_modules\//,
                use: [
                    {
                        loader: 'ts-loader',
                        options: {
                            transpileOnly: true,
                            configFile: path.resolve(__dirname, 'tsconfig.json'),
                        },
                    },
                ],
            },
            {
                test: /\.(css)$/,
                use: ['style-loader', 'css-loader'],
            },
            {
                test: /\.(png|jpg|jpeg|gif|svg|woff2?|ttf|eot|otf)(\?.*$|$)/,
                type: 'asset/resource',
                generator: {
                    filename: isProd ? 'assets/[contenthash][ext]' : 'assets/[name][ext]',
                },
            },
            {
                test: /\.(m?js)$/,
                resolve: {
                    fullySpecified: false,
                },
            },
        ],
    },
    devServer: {
        port: 9001,
        // Allow Bridge running in a container to connect to the plugin dev server.
        allowedHosts: 'all',
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
            'Access-Control-Allow-Headers': 'X-Requested-With, Content-Type, Authorization',
        },
        devMiddleware: {
            // The ConsoleRemotePlugin sets a publicPath of '/api/plugins/<plugin-name>/', however when running the
            // console locally in development mode, the proxy strips off this prefix and only leaves '/', which causes
            // the plugin to not be able to find its assets.
            publicPath: '/',
        },
    },
    plugins: [
        new ConsoleRemotePlugin({
            validateSharedModules: false,
            pluginMetadata: {
                name: 'advanced-cluster-security',
                version: '0.0.1',
                displayName: 'Red Hat Advanced Cluster Security for OpenShift',
                description: 'OCP Console Plugin for Advanced Cluster Security',
                exposedModules: {
                    SecurityVulnerabilitiesPage:
                        './ConsolePlugin/SecurityVulnerabilitiesPage/Index',
                },
                dependencies: {
                    '@console/pluginAPI': '>=4.19.0',
                },
            },
            extensions: [
                {
                    type: 'console.page/route',
                    properties: {
                        exact: true,
                        path: '/security-TODO',
                        component: { $codeRef: 'SecurityVulnerabilitiesPage.Index' },
                    },
                },
                {
                    type: 'console.navigation/href',
                    properties: {
                        id: 'security-vulnerabilities',
                        name: '%plugin__console-plugin-template~Plugin Security Vulnerabilities%',
                        href: '/security-TODO',
                        perspective: 'admin',
                        section: 'home',
                    },
                },
            ],
        }),
        new CopyWebpackPlugin({
            patterns: [
                {
                    from: path.resolve(__dirname, 'locales'),
                    to: 'locales',
                    noErrorOnMissing: true,
                },
            ],
        }),
    ],
    devtool: isProd ? false : 'source-map',
    optimization: {
        chunkIds: isProd ? 'deterministic' : 'named',
        minimize: isProd,
    },
};

module.exports = config;
