import { OperationCanceledException } from 'typescript';
import { BlockcoreIdentityTools } from '../index';

test('My Identity', () => {
  var identity = new BlockcoreIdentityTools();
  var network = identity.getProfileNetwork();

  expect(network.pubKeyHash).toBe(55);
  expect(network.scriptHash).toBe(117);
  expect(network.bech32).toBe('id');
});