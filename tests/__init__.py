from pyavp import VerifiedPermissions
from os import getenv


avp=VerifiedPermissions(policy_store_id=getenv('AVS_POLICY_STORE_ID',None))
