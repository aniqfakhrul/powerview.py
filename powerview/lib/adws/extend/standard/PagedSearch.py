from ...core.connection import Connection
from ldap3 import SUBTREE, DEREF_ALWAYS
from ldap3.utils.dn import safe_dn

def adws_paged_search_generator(connection,
                           search_base,
                           search_filter,
                           search_scope=SUBTREE,
                           dereference_aliases=DEREF_ALWAYS,
                           attributes=None,
                           size_limit=0,
                           time_limit=0,
                           types_only=False,
                           get_operational_attributes=False,
                           controls=None,
                           paged_size=100,
                           paged_criticality=False):
    if connection.check_names and search_base:
        search_base = safe_dn(search_base)

    responses = []
    cookie = None
    total_results = 0
    while True:
        results = connection.search(search_base,
                                   search_filter,
                                   search_scope,
                                   dereference_aliases,
                                   attributes,
                                   size_limit,
                                   time_limit,
                                   types_only,
                                   get_operational_attributes,
                                   controls,
                                   paged_size,
                                   paged_criticality,
                                   None if cookie is True else cookie)
        if not results:
            break
        for entry in results:
            yield entry
            total_results += 1
            if size_limit and total_results >= size_limit:
                return
        if hasattr(connection, 'last_cookie'):
            cookie = connection.last_cookie
        else:
            break
        if not cookie:
            break

def adws_paged_search_accumulator(connection,
                             search_base,
                             search_filter,
                             search_scope=SUBTREE,
                             dereference_aliases=DEREF_ALWAYS,
                             attributes=None,
                             size_limit=0,
                             time_limit=0,
                             types_only=False,
                             get_operational_attributes=False,
                             controls=None,
                             paged_size=100,
                             paged_criticality=False):
    if connection.check_names and search_base:
        search_base = safe_dn(search_base)

    return list(adws_paged_search_generator(connection,
                                           search_base,
                                           search_filter,
                                           search_scope,
                                           dereference_aliases,
                                           attributes,
                                           size_limit,
                                           time_limit,
                                           types_only,
                                           get_operational_attributes,
                                           controls,
                                           paged_size,
                                           paged_criticality))