#!/usr/bin/env node

'use strict';

const yargs = require('yargs');
const fs = require('fs');

const logger = require('log4js').getLogger();

const argv = yargs
	.alias('s', 'server').describe('server', 'The address and port of the Kubernetes API server')
	.alias('cacert', 'certificate-authority').describe('certificate-authority', 'Path to a cert. file for the certificate authority')
	.alias('cert', 'client-certificate').describe('client-certificate', 'Path to a client certificate file for TLS')
	.alias('key', 'client-key').describe('client-key', 'Path to a client key file for TLS')
	.boolean('insecure-skip-tls-verify').describe('insecure-skip-tls-verify', 'If true, the server\'s certificate will not be checked for validity. This will make your HTTPS connections insecure')
	.describe('token', 'Bearer token for authentication to the API server')
	.help()
	.argv;

/** The basic configuration for accessing the API server */
let k8sConfig;
if (argv.server) {
	const fs = require('fs');

	k8sConfig = {
		url: argv.server,
		insecureSkipTlsVerify: argv.insecureSkipTlsVerify
	};
	if (argv.certificateAuthority) {
		k8sConfig.ca = fs.readFileSync(argv.certificateAuthority, 'utf8');
	}
	if (argv.token) {
		k8sConfig.auth = { bearer: argv.token };
	} else if (argv.username && argv.password) {
		k8sConfig.auth = { user: argv.username, pass: argv.password };
	} else if (argv.clientCertificate && argv.clientKey) {
		k8sConfig.cert = fs.readFileSync(argv.clientCertificate, 'utf8');
		k8sConfig.key = fs.readFileSync(argv.clientKey, 'utf8');
	}
} else if (process.env.KUBERNETES_SERVICE_HOST) {
	k8sConfig = {
		url: `https://${process.env.KUBERNETES_SERVICE_HOST}:${process.env.KUBERNETES_SERVICE_PORT}`,
		ca: fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', 'utf8'),
		auth: { bearer: fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token', 'utf8') }
	}
} else {
	logger.error('Unknown Kubernetes API server');
	process.exit(1);
}

const k8s = require('auto-kubernetes-client');

k8s(k8sConfig).then(function(k8sClient) {
	// Main "loop": list nodes, and watch for changes. When watching finishes: re-sync.
	// All nodes are checked that they exist in the security group, and removed nodes get removed
	// from the security group as well.
	// A config map is used to keep track of the "managed" nodes, this config map is created if needed.
	const nodes = k8sClient.nodes;

	function mainLoop() {
		nodes.list().then(function(nodeList) {
			logger.info(`Processing ${nodeList.items.length} nodes at version ${nodeList.metadata.resourceVersion}`);
			nodeList.items.forEach(function(node) {
				
			});

			logger.info('Watching nodes...');
			nodes.watch(nodeList.metadata.resourceVersion)
				.on('data', function(item) {
					switch (item.type) {
					case 'ADDED':
					case 'DELETED':
					case 'MODIFIED':
						break;
					default:
						logger.warn(`Unkown watch event type ${item.type}, ignoring`);
					}
				})
				.on('end', function() {
					// Restart the whole thing.
					logger.info('Watch ended, re-syncing everything');
					return mainLoop();
				});
		});
	}

	// Start!
	mainLoop();
}).catch(function(err) {
	logger.error(`Uncaught error, aborting: ${err.message}`);
	process.exit(1);
});
