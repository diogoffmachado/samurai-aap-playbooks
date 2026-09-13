#!/usr/bin/python
"""Read guest storage evidence; provider identities are never inferred from device names."""
from datetime import datetime, timezone
import json
import os
import stat
import urllib.request

from ansible.module_utils.basic import AnsibleModule


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def azure_observation():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
                                     headers={'Metadata': 'true'})
    with opener.open(request, timeout=5) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Azure metadata response exceeded its bound')
    compute = json.loads(raw)
    links = []
    for base, _, names in os.walk('/dev/disk/azure'):
        for name in names:
            path = os.path.join(base, name)
            if os.path.islink(path):
                target = os.path.realpath(path)
                try:
                    is_block = stat.S_ISBLK(os.stat(target).st_mode)
                except OSError:
                    is_block = False
                links.append({'path': path, 'target': target, 'is_block': is_block})
    with open('/sys/class/dmi/id/product_uuid', encoding='ascii') as source:
        product_uuid = source.read(100).strip()
    return {'host': {'product_uuid': product_uuid}, 'cloud': {'provider': 'azure',
        'instance_id': compute.get('resourceId'), 'vm_id': compute.get('vmId'),
        'storage_profile': compute.get('storageProfile'), 'device_links': sorted(links, key=lambda row: row['path'])}}


def main():
    module = AnsibleModule(argument_spec={'provider': {'type': 'str', 'choices': ['aws', 'azure'], 'required': True},
        'organization_id': {'type': 'int', 'required': True}}, supports_check_mode=True)
    if module.params['organization_id'] <= 0:
        module.fail_json(msg='An organization is required for destination observation')
    rc, output, _ = module.run_command(['lsblk', '--json', '--bytes', '--paths', '--output',
                                       'NAME,SERIAL,SIZE,TYPE,FSTYPE,MOUNTPOINTS'])
    if rc:
        module.fail_json(msg='Destination block devices could not be observed')
    try:
        observation = json.loads(output)
        observer = {'aws': lambda: {}, 'azure': azure_observation}[module.params['provider']]
        observation.update(observer())
        observation.update(organization_id=module.params['organization_id'],
                           observed_at=datetime.now(timezone.utc).isoformat())
    except (ValueError, OSError, KeyError, TypeError):
        module.fail_json(msg='Destination guest identity or storage evidence is incomplete')
    module.exit_json(changed=False, observation=observation)


if __name__ == '__main__':
    main()
