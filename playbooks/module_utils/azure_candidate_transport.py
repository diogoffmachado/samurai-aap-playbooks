"""Explicit Azure service-principal transport used only inside the AAP worker."""
import json
import os
from urllib.parse import urlencode
from uuid import UUID

class AzureCandidateError(RuntimeError):
    pass


class AzureCandidatePending(RuntimeError):
    pass


class AzureCandidateTransport:
    def __init__(self, module, context):
        self.module, self.context = module, context
        module.params.update(follow_redirects='none', validate_certs=True,
                             url_username=None, url_password=None, force_basic_auth=False)
        self.writes = 0
        self.subscription = str(UUID(context['account_id']))
        tenant = str(UUID(os.environ.get('AZURE_TENANT_ID', '')))
        client = str(UUID(os.environ.get('AZURE_CLIENT_ID', '')))
        secret = os.environ.get('AZURE_CLIENT_SECRET', '')
        if (os.environ.get('AZURE_SUBSCRIPTION_ID') != self.subscription or not secret
                or os.environ.get('AZURE_AUTH_SOURCE') != 'env'
                or os.environ.get('AZURE_CLOUD_ENVIRONMENT') != 'AzureCloud'):
            raise AzureCandidateError('Explicit Azure destination credentials are required')
        token = self._request('POST', f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
            data=urlencode({'grant_type': 'client_credentials', 'client_id': client,
                            'client_secret': secret, 'scope': 'https://management.azure.com/.default'}),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}, statuses=(200,))
        self._token = token.get('access_token')
        if not isinstance(self._token, str) or not self._token:
            raise AzureCandidateError('Azure authentication returned no access token')
        account = self.get(f'/subscriptions/{self.subscription}', '2022-12-01')
        if (account.get('subscriptionId') != self.subscription or account.get('tenantId') != tenant
                or account.get('state') != 'Enabled'):
            raise AzureCandidateError('Azure did not confirm the authorized destination tenant and subscription')

    def _request(self, method, url, *, data=None, headers=None, statuses=(200,)):
        from ansible.module_utils.urls import fetch_url

        response, info = fetch_url(self.module, url, data=data, headers=headers,
                                  method=method, timeout=30, use_netrc=False)
        status = info.get('status')
        if status not in statuses:
            raise AzureCandidateError(f'Azure {method} returned HTTP {status}; reconcile owned resources before retry')
        if status == 404:
            return None
        try:
            raw = response.read(2 * 1024 * 1024 + 1) if response else b''
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError()
            value = json.loads(raw) if raw else {}
            if not isinstance(value, dict):
                raise ValueError()
        except (ValueError, UnicodeError):
            raise AzureCandidateError('Azure returned an incomplete resource document') from None
        return value

    def request(self, method, identity, version, body=None, *, optional=False, expand=None):
        root = f'/subscriptions/{self.subscription}'
        if (method not in {'GET', 'PUT', 'DELETE'} or not isinstance(identity, str)
                or not (identity.casefold() == root or identity.casefold().startswith(root + '/'))
                or any(c in identity for c in ('?', '#', '%', '\\'))
                or any(part in {'', '.', '..'} for part in identity[1:].split('/'))):
            raise AzureCandidateError('Azure operation is outside the destination subscription')
        if expand not in (None, 'instanceView', 'ReplicationStatus') or (expand and method != 'GET'):
            raise AzureCandidateError('Unsupported Azure resource expansion')
        if method in {'PUT', 'DELETE'}:
            self.writes += 1
        value = self._request(method, 'https://management.azure.com' + identity + '?' + urlencode(
            {'api-version': version, **({'$expand': expand} if expand else {})}),
            data=json.dumps(body) if body is not None else None,
            headers={'Authorization': 'Bearer ' + self._token, 'Content-Type': 'application/json',
                     **({'If-None-Match': '*'} if method == 'PUT' else {})},
            statuses=(200, 202, 204, 404) if method == 'DELETE' else
                     ((200, 201, 202) if method == 'PUT' else ((200, 404) if optional else (200,))))
        if value is not None and ('id' in value or method == 'GET'):
            if str(value.get('id', '')).casefold() != identity.casefold():
                raise AzureCandidateError('Azure returned another resource identity')
        return value

    def get(self, identity, version, *, optional=False, expand=None):
        return self.request('GET', identity, version, optional=optional, expand=expand)

    def put(self, identity, version, body):
        return self.request('PUT', identity, version, body)

    def delete(self, identity, version):
        return self.request('DELETE', identity, version)
