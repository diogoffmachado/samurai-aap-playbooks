"""Remove only frozen Azure resource generations after their backup is confirmed."""
import hashlib
import json
from uuid import UUID

from ansible.module_utils.azure_candidate_transport import AzureCandidateError, AzureCandidatePending

KINDS = {'disk': ('microsoft.compute', 'disks', '2025-01-02', 'uniqueId'),
         'nic': ('microsoft.network', 'networkinterfaces', '2025-05-01', 'resourceGuid'),
         'public_ip': ('microsoft.network', 'publicipaddresses', '2025-05-01', 'resourceGuid')}
VM_VERSION = '2025-04-01'


class AzureCleanup:
    def __init__(self, client, *, organization_id, execution_id, action, context, keep_snapshot):
        self.client, self.context, self.manifest, self.keep = client, context, context.get('manifest'), keep_snapshot
        manifest = self.manifest
        if (context.get('provider') != 'azure' or not isinstance(manifest, dict)
                or type(organization_id) is not int or organization_id <= 0
                or manifest.get('organization_id') != organization_id or manifest.get('execution_id') != execution_id
                or manifest.get('action') != action or action not in {'candidate_teardown', 'decommission'}
                or context.get('instance_id') != manifest.get('instance_id')
                or not isinstance(manifest.get('resources'), list) or type(keep_snapshot) is not bool):
            raise AzureCandidateError('Azure cleanup has no matching frozen resource manifest')
        self.org, self.execution, self.action = organization_id, execution_id, action
        self.instance = self._id(manifest['instance_id'], 'microsoft.compute', 'virtualmachines')
        self.instance_uuid = str(UUID(manifest['instance_uuid']))
        self.resources = sorted(manifest['resources'], key=lambda r: {'disk': 0, 'nic': 1, 'public_ip': 2}.get(r.get('kind'), 3))
        if sum(r.get('kind') == 'disk' and r.get('role') == 'ROOT' for r in self.resources) != 1:
            raise AzureCandidateError('Cleanup must include the observed OS disk')
        seen = {self.instance.casefold()}
        for resource in self.resources:
            kind = KINDS.get(resource.get('kind'))
            if kind is None:
                raise AzureCandidateError('Cleanup contains an unsupported resource kind')
            identity = self._id(resource.get('id'), kind[0], kind[1])
            if identity.casefold() in seen or not resource.get('region'):
                raise AzureCandidateError('Cleanup resource identity is repeated or incomplete')
            str(UUID(resource['generation']))
            seen.add(identity.casefold())

    def _id(self, value, namespace, kind):
        parts = value[1:].split('/') if isinstance(value, str) and value.startswith('/') else []
        if (len(parts) != 8 or parts[0].casefold() != 'subscriptions' or parts[1].casefold() != self.client.subscription
                or parts[2].casefold() != 'resourcegroups' or parts[4].casefold() != 'providers'
                or parts[5].casefold() != namespace or parts[6].casefold() != kind
                or any(p in {'', '.', '..'} for p in parts) or any(c in value for c in ('?', '#', '%', '\\'))):
            raise AzureCandidateError('Cleanup resource is outside its frozen subscription or type')
        return value

    def _observe(self, resource, *, require_owner=False):
        kind = KINDS[resource['kind']]
        value = self.client.get(resource['id'], kind[2], optional=True)
        if value is None:
            return None
        properties = value.get('properties') or {}
        if (str(properties.get(kind[3], '')).lower() != resource['generation'].lower()
                or value.get('location', '').lower() != resource['region'].lower()):
            raise AzureCandidateError('Cleanup resource was replaced or moved')
        if any((value.get('tags') or {}).get(k) != v for k, v in resource.get('ownership', {}).items()):
            raise AzureCandidateError('Cleanup resource ownership changed')
        if require_owner:
            owner = value.get('managedBy') if resource['kind'] == 'disk' else (
                (properties.get('virtualMachine') or {}).get('id') if resource['kind'] == 'nic'
                else (properties.get('ipConfiguration') or {}).get('id'))
            if not resource.get('attached_to') or str(owner).casefold() != resource['attached_to'].casefold():
                raise AzureCandidateError('Cleanup resource attachment changed')
        return value

    def _snapshot(self, resource):
        name = 'ss-cleanup-' + hashlib.sha256(json.dumps(
            [self.org, self.execution, self.action, resource['id'], resource['generation']],
            separators=(',', ':')).encode()).hexdigest()[:40]
        identity = '/'.join(resource['id'].split('/')[:5]) + '/providers/Microsoft.Compute/snapshots/' + name
        tags = {'managed_by': 'samurai-shield', 'samurai_organization_id': str(self.org),
                'samurai_cleanup_execution_id': str(self.execution), 'samurai_source_disk_uuid': resource['generation']}
        snapshot = self.client.get(identity, '2025-01-02', optional=True)
        if snapshot is None:
            disk = self._observe(resource)
            if disk is None:
                raise AzureCandidateError('Cleanup disk is absent before its backup was confirmed')
            properties = {'creationData': {'createOption': 'Copy', 'sourceResourceId': resource['id']}}
            if resource.get('encryption'):
                properties['encryption'] = resource['encryption']
            self.client.put(identity, '2025-01-02', {'location': resource['region'], 'tags': tags, 'properties': properties})
            raise AzureCandidatePending('Cleanup backup requested; waiting for independent observation')
        properties = snapshot.get('properties') or {}
        if (any((snapshot.get('tags') or {}).get(k) != v for k, v in tags.items())
                or str((properties.get('creationData') or {}).get('sourceResourceId', '')).casefold() != resource['id'].casefold()
                or properties.get('provisioningState') in {'Failed', 'Canceled'}):
            raise AzureCandidateError('Cleanup snapshot belongs to another resource or failed')
        if properties.get('provisioningState') != 'Succeeded':
            raise AzureCandidatePending('Cleanup snapshot is not ready')
        if type(properties.get('diskSizeGB')) is not int or properties['diskSizeGB'] < resource['size_gb']:
            raise AzureCandidateError('Cleanup snapshot geometry is incomplete')
        return identity

    def cleanup(self):
        vm = self.client.get(self.instance, VM_VERSION, optional=True)
        if vm is not None and (str((vm.get('properties') or {}).get('vmId', '')).lower() != self.instance_uuid
                or any((vm.get('tags') or {}).get(k) != v for k, v in self.manifest.get('vm_ownership', {}).items())):
            raise AzureCandidateError('Cleanup VM was replaced')
        snapshots = [self._snapshot(r) for r in self.resources if self.keep and r['kind'] == 'disk' and r.get('role') == 'ROOT']
        if vm is not None:
            for resource in self.resources:
                if self._observe(resource, require_owner=True) is None:
                    raise AzureCandidateError('Cleanup resource disappeared before VM removal')
            self.client.delete(self.instance, VM_VERSION)
            raise AzureCandidatePending('VM deletion requested; absence is not yet confirmed')
        for resource in self.resources:
            value = self._observe(resource)
            if value is None:
                continue
            props = value.get('properties') or {}
            owner = value.get('managedBy') if resource['kind'] == 'disk' else (
                (props.get('virtualMachine') or {}).get('id') if resource['kind'] == 'nic'
                else (props.get('ipConfiguration') or {}).get('id'))
            if owner:
                allowed_owner = self.instance if resource['kind'] != 'public_ip' else None
                if allowed_owner and str(owner).casefold() != allowed_owner.casefold():
                    raise AzureCandidateError('Cleanup resource is now attached to another VM')
                raise AzureCandidatePending('Cleanup resource attachment has not been released')
            self.client.delete(resource['id'], KINDS[resource['kind']][2])
            raise AzureCandidatePending('Resource deletion requested; absence is not yet confirmed')
        return {'ready': True, 'schema': 'samurai.azure-cleanup/v1', 'organization_id': self.org,
                'execution_id': self.execution, 'instance_id': self.instance, 'instance_uuid': self.instance_uuid,
                'resources_absent': [r['id'] for r in self.resources],
                'retained_snapshot_ids': snapshots, 'backup_requested': self.keep}
