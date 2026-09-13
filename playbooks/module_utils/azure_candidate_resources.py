"""Create missing resources; existing resources require ownership and intent proof."""
from ansible.module_utils.azure_candidate_transport import AzureCandidateError, AzureCandidatePending

COMPUTE = '2025-04-01'
NETWORK = '2025-05-01'
DISK = '2025-01-02'


def same_intent(expected, observed):
    if isinstance(expected, dict):
        return isinstance(observed, dict) and all(k in observed and same_intent(v, observed[k]) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(observed, list) and len(expected) == len(observed) and all(
            same_intent(a, b) for a, b in zip(expected, observed))
    if isinstance(expected, str) and expected.startswith('/subscriptions/'):
        return isinstance(observed, str) and expected.casefold() == observed.casefold()
    return type(expected) is type(observed) and expected == observed


class AzureCandidateResources:
    def __init__(self, client, spec):
        self.client, self.spec = client, spec
        self.owned_ids, self.requested_ids = [], []

    def ensure(self, identity, version, body, *, expected=None):
        observed = self.client.get(identity, version, optional=True)
        if observed is None:
            self.requested_ids.append(identity)
            self.client.put(identity, version, body)
            raise AzureCandidatePending('Azure resource creation requested; observation is still required')
        tags = observed.get('tags')
        if not isinstance(tags, dict) or any(tags.get(k) != v for k, v in body['tags'].items()):
            raise AzureCandidateError('Existing destination resource ownership or frozen intent differs')
        self.owned_ids.append(identity)
        state = (observed.get('properties') or {}).get('provisioningState')
        if state in {'Failed', 'Canceled', 'Deleting'}:
            raise AzureCandidateError('Owned destination resource is failed or being removed')
        if state != 'Succeeded':
            raise AzureCandidatePending('Azure destination resource has not completed provisioning')
        if not same_intent(expected or body, observed):
            raise AzureCandidateError('Observed destination resource differs from the frozen specification')
        return observed

    def body(self, properties, *, tags=None, **fields):
        return {'location': self.spec.region, 'tags': {**self.spec.tags, **(tags or {})},
                'properties': properties, **fields}

    def check_network(self):
        group = self.client.get(self.spec.group_id, '2021-04-01')
        if (group.get('properties') or {}).get('provisioningState') != 'Succeeded':
            raise AzureCandidateError('Destination Resource Group is not ready')
        nsg = self.client.get(self.spec.nsg, NETWORK)
        subnet = self.client.get(self.spec.subnet, NETWORK)
        vnet_id = '/'.join(self.spec.subnet.split('/')[:-2])
        vnet = self.client.get(vnet_id, NETWORK)
        for resource in [group, nsg, subnet, vnet]:
            tags = resource.get('tags') or {}
            if not isinstance(tags, dict) or any(str(v) != str(self.spec.org) for k, v in tags.items()
                if k.casefold() in {'samuraiorganizationid', 'samurai_organization_id', 'organization_id'}):
                raise AzureCandidateError('Destination network scope declares another organization')
        if (any(r.get('location') != self.spec.region or (r.get('properties') or {}).get('provisioningState') != 'Succeeded'
                for r in [nsg, vnet]) or (subnet.get('properties') or {}).get('provisioningState') != 'Succeeded'
                or (subnet.get('properties') or {}).get('delegations')):
            raise AzureCandidateError('Frozen destination network is unavailable in its region')

    def interface(self):
        config = {'privateIPAllocationMethod': 'Dynamic', 'subnet': {'id': self.spec.subnet}, 'primary': True}
        public_id = None
        if self.spec.block['public_ip']:
            public_id = self.spec.resource('Microsoft.Network', 'publicIPAddresses', self.spec.name + '-ip')
            self.ensure(public_id, NETWORK, self.body({'publicIPAllocationMethod': 'Static',
                'publicIPAddressVersion': 'IPv4'}, sku={'name': 'Standard'}))
            config['publicIPAddress'] = {'id': public_id}
        identity = self.spec.resource('Microsoft.Network', 'networkInterfaces', self.spec.name + '-nic')
        self.ensure(identity, NETWORK, self.body({'networkSecurityGroup': {'id': self.spec.nsg},
            'ipConfigurations': [{'name': 'primary', 'properties': config}]}))
        return identity, public_id

    def data_disks(self):
        attachments, observed = [], {}
        slots = sorted((s for s in self.spec.slots if s['role'] != 'ROOT'), key=lambda s: s['slot_id'])
        for lun, slot in enumerate(slots):
            identity = self.spec.resource('Microsoft.Compute', 'disks', self.spec.name + '-data-' + str(lun))
            if identity.casefold() == str(slot.get('source_volume_stable_id', '')).casefold():
                raise AzureCandidateError('Destination disk must differ from its source')
            properties = {'creationData': {'createOption': 'Empty'}, 'diskSizeGB': slot['size_gb']}
            key = (slot.get('provider') or {}).get('disk_encryption_set_id')
            if key:
                key = self.spec.reference(key, 'Microsoft.Compute', {('diskEncryptionSets',)})
                des = self.client.get(key, DISK)
                encryption_type = (des.get('properties') or {}).get('encryptionType')
                if (des.get('location') != self.spec.region or (des.get('properties') or {}).get('provisioningState') != 'Succeeded'
                        or encryption_type not in {'EncryptionAtRestWithCustomerKey', 'EncryptionAtRestWithPlatformAndCustomerKeys'}):
                    raise AzureCandidateError('Destination encryption is not ready for this data disk')
                properties['encryption'] = {'type': encryption_type, 'diskEncryptionSetId': key}
            tags = {'samurai_destination_slot_id': slot['slot_id']}
            item = self.spec.items.get(slot['slot_id'])
            if item:
                tags.update(samurai_plan_id=str(self.spec.plan['id']), samurai_plan_revision=str(self.spec.plan['revision']),
                            samurai_plan_digest=self.spec.plan['digest'])
            value = self.ensure(identity, DISK, self.body(properties, sku={'name': slot['volume_type']}, tags=tags))
            if (value.get('managedBy') is not None and str(value['managedBy']).casefold() != self.spec.vm_id.casefold()) or value.get('managedByExtended'):
                raise AzureCandidateError('Destination disk is attached to another or multiple machines')
            attachments.append({'lun': lun, 'name': identity.rsplit('/', 1)[-1], 'createOption': 'Attach',
                                'caching': 'None', 'deleteOption': 'Detach', 'managedDisk': {'id': identity}})
            observed[slot['slot_id']] = (identity, lun)
        return attachments, observed
