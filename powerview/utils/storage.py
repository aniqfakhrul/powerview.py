#!/usr/bin/env python3
import json
import os
import hashlib
from datetime import datetime, timedelta
import logging
from ldap3.utils.ciDict import CaseInsensitiveDict
import base64

from powerview.utils import paths

class Storage:
    def __init__(self):
        self.root_folder = paths.base_dir()
        self.storage_folder = paths.storage_dir()
        self.cache_folder = "ldap_cache"
        self.cache_path = paths.cache_dir()
        try:
            os.makedirs(self.cache_path, mode=0o700, exist_ok=True)
            logging.debug(f"[Storage] Using cache directory: {self.cache_path}")
            self._cleanup_expired_cache()
        except Exception as e:
            logging.error(f"[Storage] Cache initialisation failed: {e}")

    def _generate_cache_key(self, search_base, search_filter, search_scope, attributes, host, raw=False):
        """Generate a unique cache key based on search parameters"""
        cache_string = f"{search_base.lower()}|{search_filter.lower()}|{search_scope.lower()}|{str(sorted(attributes) if attributes else 'None')}|{host.lower()}|{raw}"
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

    def _cleanup_expired_cache(self, cache_ttl=1800):
        """Remove expired cache files on startup."""
        removed = 0
        cutoff = datetime.now() - timedelta(seconds=cache_ttl)
        try:
            for entry in os.scandir(self.cache_path):
                if not entry.name.endswith('.json'):
                    continue
                try:
                    with open(entry.path, 'r') as f:
                        data = json.load(f)
                    if datetime.fromisoformat(data['timestamp']) < cutoff:
                        os.remove(entry.path)
                        removed += 1
                except Exception:
                    # Unreadable or malformed cache file — remove it
                    try:
                        os.remove(entry.path)
                        removed += 1
                    except Exception:
                        pass
        except Exception as e:
            logging.debug(f"[Storage] Cache cleanup failed: {e}")
        if removed:
            logging.debug(f"[Storage] Removed {removed} expired cache file(s) on startup")

    def cache_results(self, search_base, search_filter, search_scope, attributes, host, results, raw=False):
        """Cache LDAP query results"""
        cache_key = self._generate_cache_key(search_base, search_filter, search_scope, attributes, host, raw)
        cache_file = os.path.join(self.cache_path, f"{cache_key}.json")

        try:
            serialized_results = self._serialize_complex_types(results)
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'raw': raw,
                'search_base': search_base,
                'search_filter': search_filter,
                'search_scope': search_scope,
                'attributes': attributes,
                'host': host,
                'results': serialized_results
            }

            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=4)
        except Exception as e:
            logging.error(f"Error caching results: {e}")

    def get_cached_results(self, search_base, search_filter, search_scope, attributes, host, cache_ttl=1800, raw=False):
        """Retrieve cached LDAP query results if they exist and are not expired"""
        cache_key = self._generate_cache_key(search_base, search_filter, search_scope, attributes, host, raw)
        cache_file = os.path.join(self.cache_path, f"{cache_key}.json")

        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                
                cache_time = datetime.fromisoformat(cached_data['timestamp'])
                if datetime.now() - cache_time < timedelta(seconds=cache_ttl):
                    return self._deserialize_complex_types(cached_data['results'])
                else:
                    try:
                        os.remove(cache_file)
                        logging.debug(f"[Storage] Deleted expired cache file: {cache_key}")
                    except Exception as e:
                        logging.error(f"[Storage] Error deleting expired cache file: {e}")
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