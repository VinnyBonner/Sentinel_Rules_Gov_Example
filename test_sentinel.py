from __future__ import annotations
import os
import platform
import traceback
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.core.credentials import AccessToken, TokenCredential
from azure.mgmt.securityinsight import SecurityInsights
import requests
import time
import json

SUBSCRIPTION_ID = '<SUBSCRIPTION_ID>'
RESOURCE_GRP = '<RESOURCE_GROUP_NAME>'
WORKSPACES = ['<WORKSPACE_NAME>']
CLIENT_ID = '<CLIENT_ID>'
TENANT_ID = '<TENANT_ID>'


AZURE_GOVERNMENT_AUTHORITY = "https://login.microsoftonline.us/"
AZURE_GOVERNMENT_MANAGEMENT = "https://management.usgovcloudapi.net"
SCOPE = "https://management.usgovcloudapi.net/.default"

class Sentinel:
    """Use RestAPI to communicate with Sentinel directly"""

    def __init__(self, secret: str) -> None:
        """Info needed to connect, authenticate to Sentinel"""

        self.creds = ClientSecretCredential(tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=secret, authority=AZURE_GOVERNMENT_AUTHORITY, base_url=AZURE_GOVERNMENT_MANAGEMENT)

    def __enter__(self) -> Sentinel:
        if 'Windows' in platform.system():  # avoid certificate validation on Windows???
            os.environ['REQUESTS_CA_BUNDLE'] = ''
            os.environ['CURL_CA_BUNDLE'] = ''
        try:
            self.client = SecurityInsights(credential=self.creds, subscription_id=SUBSCRIPTION_ID, base_url=AZURE_GOVERNMENT_MANAGEMENT, credential_scopes=[SCOPE])
        except (ValueError, ClientAuthenticationError) as err:
            print(f'unable to authenticate to sentinel: {err}')
        return self

    def __exit__(self, exc_type: type, exc_val: Exception, exc_tb: traceback) -> bool:
        """Log any exceptions and make the client unusable"""

        self.client = None
        return False

    def get_rules(self) -> list[str]:
        rules = []
        for space in WORKSPACES:
            try:
                rules += self.client.alert_rules.list(RESOURCE_GRP, space)
            except (ClientAuthenticationError, HttpResponseError) as err:
                print(f'unable to list Sentinel alerts for {space}: {err}')
        return rules


def main() -> None:
    with Sentinel(input('secret value: ')) as sentinel:
        rules = sentinel.get_rules()
        print(json.dumps(rules, indent=3, default=lambda x: x.__dict__ if hasattr(x, '__dict__') else str(x)))
        
if __name__ == '__main__':
    main()
