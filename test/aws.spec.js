import test from 'tape-catch';
import * as aws from '../src/aws';

function makeNode(status, name = 'ns/test') {
	const tmp = name.split('/');
	return Object.assign({ metadata: { namespace: tmp[0], name: tmp[1] }}, status);
}

test('getNodeAddress returns empty for missing addresses', assert => {
	const node = makeNode({
		status: {
			addresses: [
			]
		}
	});
	assert.notOk(aws.getNodeAddress(node));
	assert.end();
});

test('getNodeAddress returns preferred type when available', assert => {
	const node = makeNode({
		status: {
			addresses: [
				{ type: 'ExternalIP', address: 'external' },
				{ type: 'InternalIP', address: 'internal' }
			]
		}
	});
	assert.deepEqual(aws.getNodeAddress(node), { type: 'ExternalIP', address: 'external' });
	assert.end();
});

test('getNodeAddress returns preferred type when unspecific types are available', assert => {
	const node = makeNode({
		status: {
			addresses: [
				{ type: 'SomethingWeird', address: 'other' },
				{ type: 'ExternalIP', address: 'external' }
			]
		}
	});
	
	assert.deepEqual(aws.getNodeAddress(node), { type: 'ExternalIP', address: 'external' });
	assert.end();
});

test('getNodeAddress returns less preferred type when preferred type is not available and unspecific types are available', assert => {
	const node = makeNode({
		status: {
			addresses: [
				{ type: 'SomethingWeird', address: 'other' },
				{ type: 'InternalIP', address: 'internal' }
			]
		}
	});
	
	assert.deepEqual(aws.getNodeAddress(node), { type: 'InternalIP', address: 'internal' });
	assert.end();
});

test('getNodeAddress returns any type when preferred types are not available and unspecific types are available', assert => {
	const node = makeNode({
		status: {
			addresses: [
				{ type: 'SomethingWeird', address: 'other' },
			]
		}
	});
	
	assert.deepEqual(aws.getNodeAddress(node), { type: 'SomethingWeird', address: 'other' });
	assert.end();
});

test('revokeEC2 calls revoke function with matched permission', assert => {
	const node = makeNode({ status: { addresses: [ { type: 'ExternalIP', address: '192.0.2.1' }]}});
	const ipPermissions = [
		{
			FromPort: 27017,
			IpProtocol: 'tcp',
			IpRanges: [
				// An address we do not care about
				{ CidrIp: 'other' },
				// The one we want
				{ CidrIp: '192.0.2.1/32' }
			]
		}
	]
	aws.revokeEC2(node, 'group', ipPermissions, function(revokeParams, cb) {
		assert.equal(revokeParams.GroupId, 'group');
		assert.equal(revokeParams.IpPermissions.length, 1);
		assert.deepEqual(revokeParams.IpPermissions[0], { FromPort: 27017, IpProtocol: 'tcp', IpRanges: [ { CidrIp: '192.0.2.1/32' }]});
		cb();
	}).then(() => assert.end());
});