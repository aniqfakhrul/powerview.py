from ..templates import LDAP_MODIFY_DN_FSTRING
from uuid import uuid4

def modify_dn_operation(fqdn,
                        dn,
                        new_relative_dn,
                        delete_old_rdn=True,
                        new_superior=None):

    modify_dn_vars = {  
        "fqdn": fqdn,
        "uuid": str(uuid4()),
        "object_ref": dn,
        "relative_dn": new_relative_dn,
        "delete_old_rdn": delete_old_rdn,
        "new_superior": new_superior
    }

    fstring = LDAP_MODIFY_DN_FSTRING.format(**modify_dn_vars)

    return fstring
    
        
        