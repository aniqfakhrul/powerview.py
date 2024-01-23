from ldap3.utils.ntlm import NtlmClient

class NtlmClient(NtlmClient):
    def __init__(self, domain, user_name, password):
        self.client_config_flags = 0
        self.exported_session_key = None
        self.negotiated_flags = None
        self.user_name = user_name
        self.user_domain = domain
        self.no_lm_response_ntlm_v1 = None
        self.client_blocked = False
        self.client_block_exceptions = []
        self.client_require_128_bit_encryption = None
        self.max_life_time = None
        self.client_signing_key = None
        self.client_sealing_key = None
        self.sequence_number = None
        self.server_sealing_key = None
        self.server_signing_key = None
        self.integrity = False
        self.replay_detect = False
        self.sequence_detect = False
        self.confidentiality = False
        self.datagram = False
        self.identity = False
        self.client_supplied_target_name = None
        self.client_channel_binding_unhashed = None
        self.unverified_target_name = None
        self._password = password
        self.server_challenge = None
        self.server_target_name = None
        self.server_target_info = None
        self.server_version = None
        self.server_av_netbios_computer_name = None
        self.server_av_netbios_domain_name = None
        self.server_av_dns_computer_name = None
        self.server_av_dns_domain_name = None
        self.server_av_dns_forest_name = None
        self.server_av_target_name = None
        self.server_av_flags = None
        self.server_av_timestamp = None
        self.server_av_single_host_data = None
        self.server_av_channel_bindings = None
        self.server_av_flag_constrained = None
        self.server_av_flag_integrity = None
        self.server_av_flag_target_spn_untrusted = None
        self.current_encoding = None
        self.client_challenge = None
        self.server_target_info_raw = None
        self.client_av_channel_bindings = None
        self.tls_channel_binding = None

    @staticmethod
    def pack_av_info(avs):
        # avs is a list of tuples, each tuple is made of av_type and av_value
        info = b''
        for av_type, av_value in avs:
            if av_type == AV_END_OF_LIST:
                continue
            info += pack('<H', av_type)
            info += pack('<H', len(av_value))
            info += av_value

        # add AV_END_OF_LIST
        info += pack('<H', AV_END_OF_LIST)
        info += pack('<H', 0)

        return info

    def compute_nt_response(self):
        if not self.user_name and not self._password:  # anonymous authentication
            return b''

        self.client_challenge = urandom(8)
        temp = b''
        temp += pack('<B', 1)  # ResponseVersion - 1 byte
        temp += pack('<B', 1)  # HiResponseVersion - 1 byte
        temp += pack('<H', 0)  # Z(2)
        temp += pack('<I', 0)  # Z(4) - total Z(6)
        temp += self.pack_windows_timestamp()  # time - 8 bytes
        temp += self.client_challenge  # random client challenge - 8 bytes
        temp += pack('<I', 0)  # Z(4)

        if self.tls_channel_binding:
            server_av_pairs_unpack = self.unpack_av_info(self.server_target_info_raw)
            server_av_pairs_unpack.append((AV_CHANNEL_BINDINGS,self.client_av_channel_bindings))
            server_av_pairs_pack = self.pack_av_info(server_av_pairs_unpack)
            self.server_target_info_raw = server_av_pairs_pack

        temp += self.server_target_info_raw
        temp += pack('<I', 0)  # Z(4)
        response_key_nt = self.ntowf_v2()
        nt_proof_str = hmac.new(response_key_nt, self.server_challenge + temp, digestmod=hashlib.md5).digest()
        nt_challenge_response = nt_proof_str + temp
        return nt_challenge_response
