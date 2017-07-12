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
	.describe('security-group-id', 'Security Group Id to manage')
	.describe('inbound-rule', 'Inbound rule to manage per node: PROTOCOL:PORT').alias('ingress', 'inbound-rule')
	.describe('outbound-rule', '[EC2-VPC] Outbound rule to manage per node: PROTOCOL:PORT').alias('egress', 'outbound-rule')	
	.boolean('dry-run').describe('dry-run', 'If true all AWS calls will use "dry-run" mode')
	.coerce('inbound-rule', arg => Array.isArray(arg) ? arg : [arg])
	.coerce('outbound-rule', arg => Array.isArray(arg) ? arg : [arg])
	.help()
	.argv;

/* Implementation Notes:
 * - IPv6 support is completely missing
 * - Really complex rules might lead to issues when matching/avoiding duplicates
 */

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

if (!argv.securityGroupId) {
	logger.error('Security Group id is required');
	process.exit(1);
}

let haveRules = false;
if (argv.inboundRule && argv.inboundRule.length > 0) {
	haveRules = true;
} else if (argv.outboundRule && argv.outboundRule.length > 0) {
	// XXX: this would only work if this is a VPC SG, but we're not responsible for testing this here. Instead we let AWS complain
	//      if they happen to not support EC2-Classic SG egress rules.
	haveRules = true;
}

if (!haveRules) {
	logger.error('At least one rule is required');
	process.exit(1);	
}

const AWS = require('aws-sdk');
const k8s = require('auto-kubernetes-client');

k8s(k8sConfig).then(function(k8sClient) {
	// Main "loop": list nodes, and watch for changes. When watching finishes: re-sync.
	// All nodes are checked that they exist in the security group, and removed nodes get removed
	// from the security group as well.
	// A config map is used to keep track of the "managed" nodes, this config map is created if needed.
	const nodes = k8sClient.nodes;
	const ec2 = new AWS.EC2();
	const aws = require('./aws');

	function createHandler(node, operation) {
		return function(err) {
			logger.error(`Cannot ${operation} node ${node.metadata.name}: ${err.message}`);
		}
	}

	function addNode(node) {
		return aws.addNodeToSecurityGroup(ec2, node, argv.securityGroupId, argv.inboundRule, argv.outboundRule, { DryRun: argv.dryRun }).catch(createHandler(node, 'add'));
	}

	function removeNode(node) {
		return aws.removeNodeFromSecurityGroup(ec2, node, argv.securityGroupId, { DryRun: argv.dryRun }).catch(createHandler(node, 'remove'));
	}

	function mainLoop() {
		nodes.list().then(function(nodeList) {
			// FIXME: Somehow we get an error here as a string, rather than the expected promise rejection.
			if (typeof nodeList !== 'object') {
				logger.error(`Cannot get nodes: ${nodeList}`);
				process.exit(1);
			}
			logger.info(`Processing ${nodeList.items.length} nodes at version ${nodeList.metadata.resourceVersion}`);
			nodeList.items.forEach(addNode);

			logger.info('Watching nodes...');
			nodes.watch(nodeList.metadata.resourceVersion)
				.on('data', function(item) {
					switch (item.type) {
					case 'ADDED':
						addNode(item.object);
						break;
					case 'DELETED':
						removeNode(item.object);
						break;
					case 'MODIFIED':
						// Ignore?
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
