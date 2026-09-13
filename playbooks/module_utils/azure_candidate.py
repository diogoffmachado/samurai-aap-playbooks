"""Azure candidate provisioning; replication and cutover remain Engine responsibilities."""
from copy import deepcopy
from ipaddress import ip_address
from uuid import UUID

from ansible.module_utils.azure_candidate_image import access_extension, image_profile, os_profile
from ansible.module_utils.azure_candidate_resources import AzureCandidateResources, COMPUTE, DISK, NETWORK
from ansible.module_utils.azure_candidate_transport import AzureCandidateError, AzureCandidatePending


class AzureCandidate:
    def __init__(self, client, spec):
        self.client, self.spec = client, spec
        self.resources = AzureCandidateResources(client, spec)

    def provision(self):
        spec, resources = self.spec, self.resources
        resources.check_network()
        os_type, os_state, root = image_profile(self.client, spec)
        profile = os_profile(spec, os_type, os_state)
        nic_id, public_id = resources.interface()
        attachments, disk_ids = resources.data_disks()
        root_storage = {'storageAccountType': root['volume_type']}
        root_key = (root.get('provider') or {}).get('disk_encryption_set_id')
        if root_key:
            root_storage['diskEncryptionSet'] = {'id': spec.reference(root_key, 'Microsoft.Compute', {('diskEncryptionSets',)})}
        properties = {'hardwareProfile': {'vmSize': spec.block['instance_type']},
            'storageProfile': {'imageReference': {'id': spec.image},
                'osDisk': {'name': spec.name + '-os', 'createOption': 'FromImage', 'deleteOption': 'Delete',
                           'diskSizeGB': root['size_gb'], 'managedDisk': root_storage}, 'dataDisks': attachments},
            'networkProfile': {'networkInterfaces': [{'id': nic_id, 'properties': {'primary': True, 'deleteOption': 'Detach'}}]}}
        if profile:
            properties['osProfile'] = profile
        body = resources.body(properties)
        expected = deepcopy(body)
        if profile:
            expected['properties']['osProfile'].pop('adminPassword', None)
        resources.ensure(spec.vm_id, COMPUTE, body, expected=expected)
        vm = self.client.get(spec.vm_id, COMPUTE, expand='instanceView')
        props = vm.get('properties') or {}
        vm_uuid = str(UUID(props.get('vmId')))
        statuses = (props.get('instanceView') or {}).get('statuses') or []
        if not any(s.get('code') == 'PowerState/running' for s in statuses):
            raise AzureCandidatePending('Candidate power state is not running')
        extension_id = spec.vm_id + '/extensions/samurai-candidate-access'
        resources.ensure(extension_id, COMPUTE, resources.body(access_extension(spec, os_type)))
        bindings = self._bindings(disk_ids, props, vm_uuid)
        private_ip, public_ip = self._addresses(nic_id, public_id)
        evidence = {'id': vm['id'], 'vm_id': vm_uuid, 'image_id': props['storageProfile']['imageReference']['id'],
                    'instance_type': props['hardwareProfile']['vmSize'], 'network_interface_id': nic_id,
                    'os_disk_id': props['storageProfile']['osDisk']['managedDisk']['id'],
                    'provisioning_state': props['provisioningState'], 'power_state': 'running'}
        return {'ready': True, 'replacement': {'created': True, 'provider': 'azure', 'instance_id': vm['id'],
                    'region': spec.region, 'availability_zone': next(iter(vm.get('zones') or []), ''),
                    'private_ip': private_ip, 'public_ip': public_ip, 'hostname': spec.block['hostname'],
                    'source_instance_id': spec.block['source_instance_id'], 'provider_evidence': evidence,
                    'execution_id': spec.attempt, 'organization_id': str(spec.org)},
                'destination_bindings': bindings}

    def _bindings(self, disk_ids, vm, vm_uuid):
        spec, result = self.spec, []
        observed = (vm.get('storageProfile') or {}).get('dataDisks')
        if not isinstance(observed, list) or len(observed) != len(disk_ids):
            raise AzureCandidateError('Candidate disk attachment inventory is incomplete')
        for slot_id, (identity, lun) in disk_ids.items():
            matches = [disk for disk in observed if disk.get('lun') == lun
                       and str((disk.get('managedDisk') or {}).get('id', '')).casefold() == identity.casefold()]
            disk = self.client.get(identity, DISK)
            properties = disk.get('properties') or {}
            if (len(matches) != 1 or str(disk.get('managedBy', '')).casefold() != spec.vm_id.casefold()
                    or disk.get('managedByExtended') or properties.get('provisioningState') != 'Succeeded'):
                raise AzureCandidateError('Candidate and destination disk disagree about exclusive ownership')
            unique_id = str(UUID(properties.get('uniqueId')))
            size = properties.get('diskSizeGB')
            if type(size) is not int or size <= 0:
                raise AzureCandidateError('Destination disk size was not observed')
            item = spec.items.get(slot_id)
            if item:
                key = (properties.get('encryption') or {}).get('diskEncryptionSetId')
                if str(key).casefold() != item['encryption_key_id'].casefold() or size * 1024**3 < item['size_bytes']:
                    raise AzureCandidateError('Destination encryption or size violates the replication intent')
                result.append({'replication_execution_id': item['replication_execution_id'],
                    'source_volume_stable_id': item['source_volume_stable_id'], 'destination_slot_id': slot_id,
                    'destination_volume_stable_id': identity, 'candidate_instance_id': spec.vm_id,
                    'size_bytes': size * 1024**3, 'encryption_key_id': key, 'provider': 'azure',
                    'provider_unique_id': unique_id, 'instance_uuid': vm_uuid, 'attached_lun': lun,
                    'availability_zone': next(iter(disk.get('zones') or []), '')})
        return result

    def _addresses(self, nic_id, public_id):
        nic = self.client.get(nic_id, NETWORK)
        props = nic.get('properties') or {}
        configs = props.get('ipConfigurations') or []
        if (str((props.get('virtualMachine') or {}).get('id', '')).casefold() != self.spec.vm_id.casefold()
                or len(configs) != 1):
            raise AzureCandidateError('Candidate network interface ownership is ambiguous')
        private = configs[0]['properties'].get('privateIPAddress')
        public = (self.client.get(public_id, NETWORK).get('properties') or {}).get('ipAddress') if public_id else ''
        for address in [private] + ([public] if public_id else []):
            try:
                parsed = ip_address(address)
                if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast or parsed.is_link_local:
                    raise ValueError()
            except ValueError:
                raise AzureCandidateError('Candidate provider address is unavailable or unusable') from None
        return private, public
