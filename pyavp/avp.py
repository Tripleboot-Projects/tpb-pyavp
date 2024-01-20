import logging
from boto3 import client
import json
from os import getenv
from contextlib import contextmanager
from uuid import uuid1


class VerifiedPermissions:
    def __init__(
        self,
        access_key: str = None,
        secret_key: str = None,
        region: str = None,
        session=None,
        botocore_config=None,
        policy_store_id: str = None,
    ) -> None:
        boto3_client_kwargs = {}
        if access_key and secret_key:
            boto3_client_kwargs["aws_access_key_id"] = access_key
            boto3_client_kwargs["aws_secret_access_key"] = secret_key
        if region:
            boto3_client_kwargs["region_name"] = region
        if botocore_config:
            boto3_client_kwargs["config"] = botocore_config

        if session:
            self.avp = session.client("verifiedpermissions", **boto3_client_kwargs)
        else:
            self.avp = client("verifiedpermissions", **boto3_client_kwargs)

        if policy_store_id:
            self.policy_store_id = policy_store_id

        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.setLevel(logging.INFO)
        self._handler = logging.StreamHandler()
        self._handler.setLevel(logging.DEBUG)
        self._formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        self._handler.setFormatter(self._formatter)
        self._logger.addHandler(self._handler)

    @contextmanager
    def _handle_avs_exceptions(self):
        try:
            yield

        except Exception as e:
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.AccessDeniedException as e:
            self._logger.info(
                "You do not have sufficient access to perform this action."
            )
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.IncompleteSignature as e:
            self._logger.info(
                "The request signature does not conform to AWS standards."
            )
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.InternalFailure as e:
            self._logger.info(
                "The request processing has failed because of an unknown error, exception or failure."
            )
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.InvalidAction as e:
            self._logger.info(
                "The action or operation requested is invalid. Verify that the action is typed correctly."
            )
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.InvalidClientTokenId as e:
            self._logger.info(
                "The X.509 certificate or AWS access key ID provided does not exist in our records."
            )
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.NotAuthorized as e:
            self._logger.info("You do not have permission to perform this action.")
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.OptInRequired as e:
            self._logger.info(
                "The AWS access key ID needs a subscription for the service."
            )
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.RequestExpired as e:
            self._logger.info(
                "The request reached the service more than 15 minutes after the date stamp on the request or more than 15 minutes after the request expiration date (such as for pre-signed URLs), or the date stamp on the request is more than 15 minutes in the future."
            )
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.ServiceUnavailable as e:
            self._logger.info(
                "The request has failed due to a temporary failure of the server."
            )
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.ThrottlingException as e:
            self._logger.info("The request was denied due to request throttling.")
            return {"success": False, "message": str(e)}

        except self.avp.exceptions.ValidationError as e:
            self._logger.info(
                "The input fails to satisfy the constraints specified by an AWS service."
            )
            return {"success": False, "message": str(e)}

    def create_policy(
        self, policy_store_id: str, statement: str, description: str = None
    ) -> dict:
        """Create a policy in a policy store. with cedar language

        Args:
            policy_store_id (str): policy store id
            statement (str): cedar policy statement
            description (str, optional): policy description. Defaults to None.

        Raises:
            ValueError: _description_

        Returns:
            dict: _description_
        """
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            r = self.avp.create_policy(
                clientToken=uuid1(),
                policyStoreId=policy_store_id,
                definition={
                    "static": {
                        "description": description,
                        "statement": statement,
                    }
                },
            )
        return r

    def create_policy_linked_template(
        self,
        policy_store_id: str,
        policy_template_id: str,
        principal_entity_type: str,
        principal_entity_id: str,
        resource_entity_type: str,
        resource_entity_id: str,
    ) -> dict:
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            r = self.avp.create_policy(
                clientToken=uuid1(),
                policyStoreId=policy_store_id,
                definition={
                    "templateLinked": {
                        "policyTemplateId": policy_template_id,
                        "principal": self._build_entity_data(
                            principal_entity_type, principal_entity_id
                        ),
                        "resource": self._build_entity_data(
                            resource_entity_type, resource_entity_id
                        ),
                    }
                },
            )
        return r

    def delete_policy(self, policy_store_id: str, policy_id: str):
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            r = self.avp.delete_policy(
                policyStoreId=policy_store_id, policyId=policy_id
            )
        return r

    def get_policy(self, policy_store_id: str, policy_id: str):
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            r = self.avp.get_policy(policyStoreId=policy_store_id, policyId=policy_id)
        return r

    def is_authorized(
        self,
        policy_store_id: str,
        principal_entity_type: str,
        principal_entity_id: str,
        action_type: str,
        action_id: str,
        resource_entity_type: str,
        resource_entity_id: str,
        entity_list: list,
        context: dict = None,
    ) -> dict:
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            r = self.avp.is_authorized(
                policyStoreId=policy_store_id,
                principal=self._build_entity_data(
                    principal_entity_type, principal_entity_id
                ),
                action=self._build_action_data(action_type, action_id),
                resource=self._build_entity_data(
                    resource_entity_type, resource_entity_id
                ),
                context=context,
                entities={"entityList": entity_list},
            )
        return r

    def is_authorized_with_token(
        self,
        policy_store_id: str,
        identity_token: str,
        access_token: str,
        principal_entity_type: str,
        principal_entity_id: str,
        action_type: str,
        action_id: str,
        resource_entity_type: str,
        resource_entity_id: str,
        entity_list: list,
        context: dict = None,
    ) -> dict:
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            r = self.avp.is_authorized(
                policyStoreId=policy_store_id,
                identityToken=identity_token,
                accessToken=access_token,
                principal=self._build_entity_data(
                    principal_entity_type, principal_entity_id
                ),
                action=self._build_action_data(action_type, action_id),
                resource=self._build_entity_data(
                    resource_entity_type, resource_entity_id
                ),
                context=context,
                entities={"entityList": entity_list},
            )
        return r

    def update_policy(
        self,
        policy_store_id: str,
        policy_id: str,
        statement: str,
        description: str = None,
    ):
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            r = client.update_policy(
                policyStoreId=policy_store_id,
                policyId=policy_id,
                definition={
                    "static": {"description": description, "statement": statement}
                },
            )

    def list_policies(
        self,
        policy_store_id: str = None,
        max_items: int = 50,
        page_size: int = 50,
        next_token: str = None,
    ):
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            paginator = self.avp.get_paginator("list_policies")
            pagination_config = {"MaxItems": max_items, "PageSize": page_size}
            if next_token is not None:
                pagination_config["StartingToken"] = next_token
            r = paginator.paginate(
                policyStoreId=policy_store_id,
                filter={},
                PaginationConfig=pagination_config,
            )

    def list_policy_templates(
        self,
        policy_store_id: str = None,
        max_items: int = 50,
        page_size: int = 50,
        next_token: str = None,
    ):
        policy_store_id = policy_store_id or self.policy_store_id
        if policy_store_id is None:
            raise ValueError("is required a policy_store_id.")
        with self._handle_avs_exceptions():
            paginator = self.avp.get_paginator("list_policy_templates")
            pagination_config = {"MaxItems": max_items, "PageSize": page_size}
            if next_token is not None:
                pagination_config["StartingToken"] = next_token
            r = paginator.paginate(
                policyStoreId=policy_store_id,
                PaginationConfig=pagination_config,
            )
        return r

    def _build_entity_data(self, entity_type: str, entity_id: str) -> dict:
        return {"entityType": entity_type, "entityId": entity_id}

    def _build_action_data(self, action_type: str, action_id: str) -> dict:
        return {"actionType": action_type, "actionId": action_id}

    def build_context_map(self):
        return {
            "contextMap": {
                "string": {
                    "boolean": True | False,
                    "entityIdentifier": {
                        "entityType": "string",
                        "entityId": "string",
                    },
                    "long": 123,
                    "string": "string",
                    "set": [
                        {"... recursive ..."},
                    ],
                    "record": {"string": {"... recursive ..."}},
                }
            }
        }

    def build_entity_list(self):
        return [
            {
                "identifier": {
                    "entityType": "string",
                    "entityId": "string",
                },
                "attributes": {
                    "string": {
                        "boolean": True | False,
                        "entityIdentifier": {
                            "entityType": "string",
                            "entityId": "string",
                        },
                        "long": 123,
                        "string": "string",
                        "set": [
                            {"... recursive ..."},
                        ],
                        "record": {"string": {"... recursive ..."}},
                    }
                },
                "parents": [
                    {"entityType": "string", "entityId": "string"},
                ],
            },
        ]
