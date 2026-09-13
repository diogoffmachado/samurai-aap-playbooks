#!/usr/bin/python
"""Execute the governed Azure cleanup manifest without changing workflow authority."""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.azure_candidate_transport import AzureCandidateTransport, AzureCandidateError, AzureCandidatePending
from ansible.module_utils.azure_cleanup import AzureCleanup


def main():
    module = AnsibleModule(argument_spec={
        'organization_id': {'type': 'int', 'required': True},
        'execution_id': {'type': 'int', 'required': True},
        'action': {'type': 'str', 'required': True},
        'context': {'type': 'dict', 'required': True},
        'keep_snapshot': {'type': 'bool', 'required': True},
    }, supports_check_mode=False)
    client = None
    try:
        arguments = dict(module.params)
        client = AzureCandidateTransport(module, arguments['context'])
        result = AzureCleanup(client, **arguments).cleanup()
    except AzureCandidatePending as exc:
        result = {'ready': False, 'reason': str(exc)}
    except AzureCandidateError as exc:
        module.fail_json(msg=str(exc), changed=bool(client and client.writes))
    except (ValueError, TypeError, KeyError, AttributeError):
        module.fail_json(msg='Azure cleanup manifest or observation is incomplete', changed=bool(client and client.writes))
    module.exit_json(**result, changed=bool(client and client.writes))


if __name__ == '__main__':
    main()
