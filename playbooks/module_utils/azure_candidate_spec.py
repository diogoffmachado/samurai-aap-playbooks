"""Validate the frozen Azure candidate intent before the worker writes resources."""
import hashlib
import json
import re
from uuid import UUID

from ansible.module_utils.azure_candidate_transport import AzureCandidateError


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class AzureCandidateSpec:
    def __init__(self, *, organization_id, attempt_id, context, block, intents, plan):
        if (type(organization_id) is not int or organization_id <= 0 or context.get('organization_id') != organization_id
                or context.get('provider') != 'azure' or context.get('attempt_id') != attempt_id
                or type(context.get('execution_id')) is not int or context['execution_id'] <= 0
                or not isinstance(attempt_id, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', attempt_id)):
            raise AzureCandidateError('Candidate execution does not match its destination context')
        self.org, self.attempt, self.context, self.block = organization_id, attempt_id, context, block
        self.subscription = str(UUID(context.get('account_id')))
        self.region = context.get('region')
        group = block.get('resource_group_name')
        if (block.get('preserve_source') is not True or not isinstance(group, str)
                or not re.fullmatch(r'[\w().-]{1,90}', group) or group.endswith('.')
                or not isinstance(self.region, str) or not re.fullmatch(r'[a-z0-9]+', self.region)
                or block.get('region') != self.region or not block.get('source_instance_id')
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', str(block.get('hostname', '')))
                or not re.fullmatch(r'[A-Za-z0-9_]+', str(block.get('instance_type', '')))):
            raise AzureCandidateError('Azure candidate placement and preserved source must be explicit')
        self.group_id = f'/subscriptions/{self.subscription}/resourceGroups/{group}'
        self.name = 'ss-' + digest([organization_id, context['execution_id'], attempt_id])[:32]
        self.vm_id = self.resource('Microsoft.Compute', 'virtualMachines', self.name)
        if self.vm_id.casefold() == str(block['source_instance_id']).casefold():
            raise AzureCandidateError('Candidate must differ from the source')
        self.image = self.reference(block.get('image_ref'), 'Microsoft.Compute', {('images',), ('galleries', 'images', 'versions')})
        self.subnet = self.reference(block.get('subnet_id'), 'Microsoft.Network', {('virtualNetworks', 'subnets')})
        groups = block.get('security_group_ids')
        if not isinstance(groups, list) or len(groups) != 1 or type(block.get('public_ip')) is not bool:
            raise AzureCandidateError('Azure requires an explicit public-IP choice and one destination NSG')
        self.nsg = self.reference(groups[0], 'Microsoft.Network', {('networkSecurityGroups',)})
        user, key = block.get('ssh_username'), block.get('ssh_public_key')
        if (not isinstance(user, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', user)
                or not isinstance(key, str) or not re.fullmatch(r'ssh-(?:rsa|ed25519) [A-Za-z0-9+/=]+(?: [A-Za-z0-9_.@-]+)?', key)
                or block.get('bootstrap') not in {'posix_shell', 'windows_powershell'}):
            raise AzureCandidateError('Candidate platform account and public key are invalid')
        self.slots, self.items = self._disks(block.get('disk_config'), intents)
        self.plan = plan
        if intents and (not isinstance(plan, dict) or not plan.get('id') or not plan.get('digest')
                        or type(plan.get('revision')) is not int or plan['revision'] <= 0):
            raise AzureCandidateError('Replicated disks require the frozen replication plan identity')
        tags = block.get('tags') or {}
        if not isinstance(tags, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or k.lower().startswith('samurai')
            or k.lower() in {'managed_by', 'organization_id'} or len(k) > 512 or len(v) > 256 for k, v in tags.items()
        ):
            raise AzureCandidateError('Blueprint tags cannot replace platform ownership metadata')
        self.tags = {**tags, 'managed_by': 'samurai-shield', 'samurai_organization_id': str(organization_id),
                     'samurai_campaign_server_execution_id': str(context['execution_id']), 'samurai_attempt_id': attempt_id,
                     'samurai_intent_digest': digest([context, block, intents, plan])}

    def resource(self, namespace, kind, name):
        return f'{self.group_id}/providers/{namespace}/{kind}/{name}'

    def reference(self, value, namespace, kinds):
        if (not isinstance(value, str) or not value.startswith('/') or value.endswith('/')
                or any(c in value for c in ('?', '#', '%', '\\')) or any(ord(c) < 33 for c in value)):
            raise AzureCandidateError('Azure resource identity is invalid')
        parts = value[1:].split('/')
        if (len(parts) < 8 or len(parts) % 2 or parts[0].lower() != 'subscriptions'
                or parts[1].lower() != self.subscription or parts[2].lower() != 'resourcegroups'
                or parts[4].lower() != 'providers' or parts[5].lower() != namespace.lower()
                or tuple(p.lower() for p in parts[6::2]) not in {tuple(k.lower() for k in kind) for kind in kinds}
                or any(p in {'', '.', '..'} for p in parts)):
            raise AzureCandidateError('Azure resource is outside the frozen destination subscription or type')
        return value

    def _disks(self, slots, intents):
        if not isinstance(slots, list) or not isinstance(intents, list):
            raise AzureCandidateError('Candidate disk intent is incomplete')
        by_slot, items = {}, {}
        for slot in slots:
            if (not isinstance(slot, dict) or not isinstance(slot.get('slot_id'), str) or not slot['slot_id']
                    or slot['slot_id'] in by_slot or slot.get('role') not in {'ROOT', 'PERSISTENT_DATA', 'EPHEMERAL'}
                    or type(slot.get('size_gb')) is not int or slot['size_gb'] <= 0
                    or slot.get('volume_type') not in {'Premium_LRS', 'StandardSSD_LRS', 'Standard_LRS', 'Premium_ZRS', 'StandardSSD_ZRS'}):
                raise AzureCandidateError('Candidate disk identity, size or type is invalid')
            by_slot[slot['slot_id']] = slot
        if sum(s['role'] == 'ROOT' for s in slots) != 1 or len(slots) > 65:
            raise AzureCandidateError('Candidate requires one ROOT slot and at most 64 data disks')
        for item in intents:
            slot = by_slot.get(item.get('destination_slot_id')) if isinstance(item, dict) else None
            if (slot is None or slot['role'] != 'PERSISTENT_DATA' or slot['slot_id'] in items
                    or not item.get('replication_execution_id') or not item.get('source_volume_stable_id')
                    or slot.get('source_volume_stable_id') != item['source_volume_stable_id']
                    or item.get('destination_size_gb') != slot['size_gb'] or item.get('destination_volume_type') != slot['volume_type']
                    or type(item.get('size_bytes')) is not int or not 0 < item['size_bytes'] <= slot['size_gb'] * 1024**3):
                raise AzureCandidateError('Replicated data must match a unique frozen slot without truncation')
            key = self.reference(item.get('encryption_key_id'), 'Microsoft.Compute', {('diskEncryptionSets',)})
            if (slot.get('provider') or {}).get('disk_encryption_set_id') != key:
                raise AzureCandidateError('Replicated disk encryption differs from the frozen slot')
            items[slot['slot_id']] = item
        return slots, items
