#!/usr/bin/python
"""Create and observe one governed Azure candidate without advancing cutover."""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.azure_candidate import AzureCandidate
from ansible.module_utils.azure_candidate_spec import AzureCandidateSpec
from ansible.module_utils.azure_candidate_transport import AzureCandidateError, AzureCandidatePending, AzureCandidateTransport


def main():
    module = AnsibleModule(argument_spec={
        'organization_id': {'type': 'int', 'required': True},
        'attempt_id': {'type': 'str', 'required': True},
        'context': {'type': 'dict', 'required': True},
        'block': {'type': 'dict', 'required': True},
        'intents': {'type': 'list', 'elements': 'dict', 'default': []},
        'plan': {'type': 'dict', 'default': {}},
    }, supports_check_mode=False)
    worker, client = None, None
    result, error = {}, None
    try:
        spec = AzureCandidateSpec(**module.params)
        client = AzureCandidateTransport(module, spec.context)
        worker = AzureCandidate(client, spec)
        result = worker.provision()
    except AzureCandidatePending as exc:
        result = {'ready': False, 'reason': str(exc)}
    except AzureCandidateError as exc:
        error = str(exc)
    except (ValueError, TypeError, KeyError, AttributeError):
        error = 'Azure candidate observation or intent is incomplete; no readiness evidence was published'
    except Exception as exc:
        error = f'Azure candidate failed with {type(exc).__name__}; reconcile the recorded resource identities'
    result['changed'] = bool(client and client.writes)
    result['owned_resource_ids'] = worker.resources.owned_ids if worker else []
    result['requested_resource_ids'] = worker.resources.requested_ids if worker else []
    if error:
        module.fail_json(msg=error, **result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
