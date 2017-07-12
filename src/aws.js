/**
 * Functions for managing nodes.
 *
 * @module aws
 */
'use strict';

// @ts-ignore
import * as AWS from 'aws-sdk';

// Kubernetes types
/**
 * @typedef Kubernetes.Metadata
 * @property {string} namespace
 * @property {string} name
 */
/**
 * @typedef Kubernetes.Address
 * @property {('ExternalIP'|'InternalIP')} type
 * @property {string} address
 */
/**
 * @typedef Kubernetes.Status
 * @property {Array<Kubernetes.Address>} addresses
 */
/**
 * @typedef Kubernetes.Node
 * @property {Kubernetes.Metadata} metadata
 * @property {Kubernetes.Status} status
 */

// AWS types
/**
 * @typedef AWS.EC2.IpRange
 * @property {string} CidrIp
 */
/**
 * @typedef AWS.EC2.IpPermission
 * @property {number} [FromPort=0]
 * @property {number} [ToPort=0]
 * @property {string} IpProtocol
 * @property {Array<AWS.EC2.IpRange>} IpRanges
 */

const logger = require('log4js').getLogger();

/**
 * Convert a rule to an array of IpPermissions objects
 *
 * @package
 * @param {any} rule
 * @param {any} nodeCidrIp
 * @returns {Array<AWS.EC2.IpPermission>}
 */
export function ruleToIpPermissions(rule, nodeCidrIp) {
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

/**
 * Extract address information from the node status.
 *
 * @package
 * @param {Kubernetes.Node} node
 * @returns
 */
export function getNodeAddress(node) {
	// Find a suitable IP for the node: ExternalIP preferably, otherwise use the InternalIP, or whatever else is there.
	const addressPreference = [ 'InternalIP', 'ExternalIP' ];
	const addresses = node.status.addresses.sort((a, b) => addressPreference.indexOf(b.type) - addressPreference.indexOf(a.type));

	const nodeAddress = addresses[0];
	if (nodeAddress.type !== 'ExternalIP') {
		logger.warn(`Cannot determine ExternalIP address of node ${node.metadata.name}, using ${nodeAddress.type} ${nodeAddress.address}`);
	}

	return nodeAddress;
}

/**
 *
 * @package
 * @param {Kubernetes.Node} node
 * @param {string} securityGroupId
 * @param {Array<any>} rules
 * @param {any} removeExistingIpPermissions
 * @param {Function} authorize
 * @param {Object} [extraParams={}]
 * @returns
 */
export function authorizeEC2(node, securityGroupId, rules, removeExistingIpPermissions, authorize, extraParams = {}) {
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
 * @export
 * @param {AWS.EC2} ec2
 * @param {Kubernetes.Node} node
 * @param {string} securityGroupId
 * @param {any} [inboundRules=[]]
 * @param {any} [outboundRules=[]]
 * @param {any} [extraParams={}]
 * @returns {Promise<Array<?>>} a promise that resolves to an array of EC2 results
 */
export function addNodeToSecurityGroup(ec2, node, securityGroupId, inboundRules = [], outboundRules = [], extraParams = {}) {
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
			 * @returns {boolean}
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

/**
 *
 * @package
 * @param {Kubernetes.Node} node
 * @param {string} securityGroupId
 * @param {Array<AWS.EC2.IpPermission>} ipPermissions
 * @param {function} ec2RevokeFunction
 * @param {Object} [extraParams={}]
 * @returns
 */
export function revokeEC2(node, securityGroupId, ipPermissions, ec2RevokeFunction, extraParams = {}) {
	const nodeCidr = `${getNodeAddress(node).address}/32`;

	// Find all ingress rules for this node
	// For each of these rules we need to reset the Cidr entry to just our node address, and then revoke them all.
	const revokeIpPermissions = ipPermissions.filter(ipPermission => ipPermission.IpRanges.findIndex(ipRange => ipRange.CidrIp === nodeCidr) !== -1).map(ipPermission => Object.assign({}, ipPermission, { IpRanges: [{ CidrIp: nodeCidr }]}));
	const revokeParams = Object.assign({}, extraParams, {
		GroupId: securityGroupId,
		IpPermissions: revokeIpPermissions
	});				
	return new Promise(function(resolve, reject) {
		return ec2RevokeFunction(revokeParams, function(err, data) {
			if (err) {
				logger.error(`Cannot revoke ingress rules for ${node.metadata.name} from ${securityGroupId}: ${err.message}`);
				return reject(err);
			} else {
				return resolve(data);
			}
		});
	});
}

/**
 *
 * @export
 * @param {AWS.EC2} ec2
 * @param {Kubernetes.Node} node
 * @param {string} securityGroupId
 * @param {any} [extraParams={}]
 */
export function removeNodeFromSecurityGroup(ec2, node, securityGroupId, extraParams = {}) {
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
