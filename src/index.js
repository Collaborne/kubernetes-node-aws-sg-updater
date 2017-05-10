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

	/**
	 * Convert a rule to an array of IpPermissions objects
	 *
	 * @param {any} rule
	 * @param {any} nodeCidrIp
	 * @returns {Array<IpPermission>}
	 */
	function ruleToIpPermissions(rule, nodeCidrIp) {
		const baseIpPermission = {
			IpRanges: [
				{
					CidrIp: nodeCidrIp
				}
			]
		};

		// FIXME: We need to verify that ICMP works here instead of ports we want to assign the types.
		const colonIndex = rule.indexOf(':');
		if (colonIndex !== -1) {
			const portRanges = rule.substring(colonIndex + 1).split(',');
			return portRanges.map(function(portRange) {
				const protocol = rule.substring(0, colonIndex);
				const dashIndex = portRange.indexOf('-');

				let fromPort, toPort;
				if (dashIndex !== -1) {
					fromPort = Number.parseInt(portRange.substring(0, dashIndex)),
					toPort = Number.parseInt(portRange.substring(dashIndex + 1))
				} else {
					fromPort = toPort = Number.parseInt(portRange);
				}
				return Object.assign({}, baseIpPermission, {
					IpProtocol: protocol,
					FromPort: fromPort,
					ToPort: toPort
				});
			});
		} else {
			return [Object.assign({}, baseIpPermission, { IpProtocol: rule })];
		}
	}

	function getNodeAddress(node) {
		// Find a suitable IP for the node: ExternalIP preferably, otherwise use the InternalIP, or whatever else is there.
		const addressPreference = [ 'InternalIP', 'ExternalIP' ];
		const addresses = node.status.addresses.sort((a, b) => addressPreference.indexOf(b.type) - addressPreference.indexOf(a.type));

		const nodeAddress = addresses[0];
		if (nodeAddress.type !== 'ExternalIP') {
			logger.warn(`Cannot determine ExternalIP address of node ${node.metadata.name}, using ${nodeAddress.type} ${nodeAddress.address}`);
		}

		return nodeAddress;
	}

	function authorizeEC2(node, securityGroupId, rules, removeExistingIpPermissions, authorize, extraParams = {}) {
		return new Promise(function(resolve, reject) {
			// Calculate the required set of permissions from the rules
			const ipPermissions = rules
				.map(rule => ruleToIpPermissions(rule, `${getNodeAddress(node).address}/32`))
				.reduce((result, ipPermissions) => result.concat(ipPermissions), [])
				.filter(removeExistingIpPermissions);

			if (ipPermissions.length > 0) {
				logger.info(`Authorizing ${node.metadata.name} for ${JSON.stringify(ipPermissions)}`);

				const params = Object.assign({}, extraParams, {
					GroupId: securityGroupId,
					IpPermissions: ipPermissions
				});
				return authorize(params, function(err, data) {
					if (err) {
						logger.error(`Cannot authorize rules for ${node.metadata.name}: ${err.message}`);
						return reject(err);
					} else {
						return resolve(data);
					}
				});
			} else {
				// Nothing to do, but that's fine.
				return resolve({});
			}
		});
	}
	
	/**
	 * Update the security group to include the rules for the node
	 *
	 * @param {any} node
	 * @param {any} securityGroupId
	 * @param {any} [inboundRules=[]]
	 * @param {any} [outboundRules=[]]
	 * @param {any} [extraParams={}]
	 * @returns {Promise<Array<?>>} a promise that resolves to an array of EC2 results
	 */
	function addNodeToSecurityGroup(node, securityGroupId, inboundRules = [], outboundRules = [], extraParams = {}) {
		// Query the existing security group for rules
		return new Promise(function(resolve, reject) {
			const params = Object.assign({}, extraParams, {
				// Avoid dry-run here: we want to query the security groups!
				DryRun: false,
				GroupIds: [securityGroupId]
			});
			return ec2.describeSecurityGroups(params, function(err, data) {
				if (err) {
					logger.error(`Cannot describe security group ${securityGroupId}: ${err.message}`);
					return reject(err);
				}

				// There should be this one security group that we wanted; still check: the group might have been removed.
				// We cannot add the node, and we cannot create the security group, so this is a clear error.
				if (data.SecurityGroups.length === 0) {
					logger.warn(`No security groups returned for id ${securityGroupId}`);
					return reject(new Error(`Missing security group ${securityGroupId}`));
				}

				const securityGroup = data.SecurityGroups[0];

				/**
				 * Return `true` if `ipPermisssion` does not exist in `existingIpPermissions`.
				 *
				 * @param {any} existingIpPermissions
				 * @param {any} ipPermissions
				 * @returns {Promise<Array<IpPermission>>}
				 */
				function doesNotContain(existingIpPermissions, ipPermission) {
					// Reverse logic: see if we can find it, and if so then we already exist.
					function isCovered(ipPermission, other) {
						if (ipPermission.IpProtocol !== other.IpProtocol) {
							return false;
						}

						if (ipPermission.FromPort > other.FromPort) {
							return false;
						}
						if (ipPermission.ToPort < other.ToPort) {
							return false;
						}

						// Covered if all IpRanges in other are also included in the ipPermission.
						// XXX: We're not CIDR-aware here, but do a string comparison only.
						for (let neededIpRange of other.IpRanges) {
							const coveringIpRange = ipPermission.IpRanges.find(ipRange => ipRange.CidrIp === neededIpRange.CidrIp);
							if (!coveringIpRange) {
								return false;
							}
						}

						logger.debug(`Found existing IpPermission ${JSON.stringify(ipPermission)} covering ${JSON.stringify(other)}`);
						return true;
					}

					return !existingIpPermissions.find(existingIpPermission => isCovered(existingIpPermission, ipPermission));
				}

				return Promise.all([
					authorizeEC2(node, securityGroupId, inboundRules, doesNotContain.bind(this, securityGroup.IpPermissions), ec2.authorizeSecurityGroupIngress.bind(ec2), extraParams),
					authorizeEC2(node, securityGroupId, outboundRules, doesNotContain.bind(this, securityGroup.IpPermissionsEgress), ec2.authorizeSecurityGroupEgress.bind(ec2), extraParams),
				]).then(results => resolve(results), err => reject(err));
			});
		});

	}

	function revokeEC2(node, securityGroupId, ipPermissions, ec2RevokeFunction, extraParams = {}) {
		const nodeCidr = `${getNodeAddress(node).address}/32`;

		// Find all ingress rules for this node
		// For each of these rules we need to reset the Cidr entry to just our node address, and then revoke them all.
		const revokeIpPermissions = ipPermissions.filter(ipPermission => ipPermission.IpRanges.indexOf(ipRange => ipRange.Cidr === nodeCidr) !== -1).map(ipPermission => Object.assign({}, ipPermission, { IpRange: { Cidr: nodeCidr }}));
		const revokeIngressParams = Object.assign({}, extraParams, {
			IpPermissions: revokeIpPermissions
		});				
		return new Promise(function(resolve, reject) {
			return ec2RevokeFunction(revokeIngressParams, function(err, data) {
				if (err) {
					logger.error(`Cannot revoke ingress rules for ${node.metadata.name} from ${securityGroupId}: ${err.message}`);
					return reject(err);
				} else {
					return resolve(data);
				}
			});
		});
	}

	function removeNodeFromSecurityGroup(node, securityGroupId, extraParams = {}) {
		// Get the security group, and find the rules for the node
		return new Promise(function(resolve, reject) {
			const params = Object.assign({}, extraParams, {
				// Avoid dry-run here: we want to query the security groups!
				DryRun: false,
				GroupIds: [securityGroupId]
			});
			return ec2.describeSecurityGroups(params, function(err, data) {
				if (err) {
					logger.error(`Cannot describe security group ${securityGroupId}: ${err.message}`);
					return reject(err);
				}

				// There should be this one security group that we wanted; still check: the group might have been removed,
				// in which case we're perfectly fine.
				if (data.SecurityGroups.length === 0) {
					logger.warn(`No security groups returned for id ${securityGroupId}`);
					return resolve({});
				}

				const securityGroup = data.SecurityGroups[0];

				return Promise.all([
					revokeEC2(node, securityGroupId, securityGroup.IpPermissions, ec2.revokeSecurityGroupIngress.bind(ec2), extraParams),
					revokeEC2(node, securityGroupId, securityGroup.IpPermissionsEgress, ec2.revokeSecurityGroupEgress.bind(ec2), extraParams),
				]);
			});
		});
	}

	function createHandler(node, operation) {
		return function(err) {
			logger.error(`Cannot ${operation} node ${node.metadata.name}: ${err.message}`);
		}
	}

	function addNode(node) {
		return addNodeToSecurityGroup(node, argv.securityGroupId, argv.inboundRule, argv.outboundRule, { DryRun: argv.dryRun }).catch(createHandler(node, 'add'));
	}

	function removeNode(node) {
		return removeNodeFromSecurityGroup(node, argv.securityGroupId, argv.inboundRule, argv.outboundRule, { DryRun: argv.dryRun }).catch(createHandler(node, 'remove'));
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
