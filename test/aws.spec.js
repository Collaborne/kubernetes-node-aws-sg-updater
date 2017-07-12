import test from 'tape-catch';
import * as aws from '../src/aws';

function makeNode(status, name = 'ns/test') {
	const tmp = name.split('/');
	return Object.assign({ metadata: { namespace: tmp[0], name: tmp[1] }}, status);
}

test('getNodeAddress returns empty for missing addresses', assert => {
	const node = makeNode({ status: { addresses: [ ] }});
	assert.notOk(aws.getNodeAddress(node));
	assert.end();
});

test('getNodeAddress returns preferred type when available', assert => {
	const node = makeNode({ status: { addresses: [ { type: 'ExternalIP', address: 'external' }, { type: 'InternalIP', address: 'internal' } ] }});
	assert.deepEqual(aws.getNodeAddress(node), { type: 'ExternalIP', address: 'external' });
	assert.end();
});