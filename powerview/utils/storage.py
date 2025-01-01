#!/usr/bin/env python3
import json
import os
import hashlib
from datetime import datetime, timedelta
import logging
from ldap3.utils.ciDict import CaseInsensitiveDict
import base64

class Storage:
    def __init__(self):
        self.root_folder = os.path.join(os.path.expanduser('~'), ".powerview", "storage")
        self.cache_folder = "ldap_cache"
        self.cache_path = os.path.join(self.root_folder, self.cache_folder)
        
        try:
            os.makedirs(self.cache_path, exist_ok=True)
        except Exception as e:
            logging.error(f"Error initializing storage: {e}")

    def _generate_cache_key(self, search_base, search_filter, search_scope, attributes):
        """Generate a unique cache key based on search parameters"""
        cache_string = f"{search_base.lower()}|{search_filter.lower()}|{search_scope.lower()}|{str(sorted(attributes) if attributes else 'None')}"
        return hashlib.md5(cache_string.encode()).hexdigest()

    def _serialize_complex_types(self, obj):
        """Serialize complex types like datetime, bytes, timedelta, and others."""
        if isinstance(obj, datetime):
            return {'__datetime__': obj.isoformat()}
        elif isinstance(obj, timedelta):
            return {'__timedelta__': obj.total_seconds()}
        elif isinstance(obj, bytes):
            return {'__bytes__': base64.b64encode(obj).decode('ascii')}
        elif isinstance(obj, dict):
            return {key: self._serialize_complex_types(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_complex_types(item) for item in obj]
        elif isinstance(obj, CaseInsensitiveDict):
            return {key: self._serialize_complex_types(value) for key, value in obj.items()}
        elif isinstance(obj, (tuple, set)):
            return list(obj)
        return obj

    def _deserialize_complex_types(self, obj):
        """Deserialize complex types like datetime, bytes, timedelta, and others."""
        if isinstance(obj, dict):
            if '__datetime__' in obj:
                return datetime.fromisoformat(obj['__datetime__'])
            elif '__timedelta__' in obj:
                return timedelta(seconds=obj['__timedelta__'])
            elif '__bytes__' in obj:
                return base64.b64decode(obj['__bytes__'].encode('ascii'))
            else:
                return {key: self._deserialize_complex_types(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._deserialize_complex_types(item) for item in obj]
        return obj

    def cache_results(self, search_base, search_filter, search_scope, attributes, results):
        """Cache LDAP query results"""
        cache_key = self._generate_cache_key(search_base, search_filter, search_scope, attributes)
        cache_file = os.path.join(self.cache_path, f"{cache_key}.json")

        try:
            serialized_results = self._serialize_complex_types(results)
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'search_base': search_base,
                'search_filter': search_filter,
                'search_scope': search_scope,
                'attributes': attributes,
                'results': serialized_results
            }

            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=4)
        except Exception as e:
            logging.error(f"Error caching results: {e}")

    def get_cached_results(self, search_base, search_filter, search_scope, attributes, cache_ttl=300):
        """Retrieve cached LDAP query results if they exist and are not expired"""
        cache_key = self._generate_cache_key(search_base, search_filter, search_scope, attributes)
        cache_file = os.path.join(self.cache_path, f"{cache_key}.json")

        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                
                cache_time = datetime.fromisoformat(cached_data['timestamp'])
                if datetime.now() - cache_time < timedelta(seconds=cache_ttl):
                    return self._deserialize_complex_types(cached_data['results'])
        except Exception as e:
            logging.error(f"[Storage] Error reading cache: {e}")
        
        return None

    def clear_cache(self) -> bool:
        """Clear all cached LDAP results"""
        try:
            for file in os.listdir(self.cache_path):
                if file.endswith('.json'):
                    os.remove(os.path.join(self.cache_path, file))
            return True
        except Exception as e:
            logging.error(f"Error clearing cache: {e}")
            return False