#
# Copyright (C) 2023 ColorTokens Inc.
# By Venky Raju <venky.raju@colortokens.com>
#
# Decodes the wfpstate.xml file produced by the command
# netsh wfp show state

import untangle
import dateutil.parser

field_key_map = {
    'FWPM_CONDITION_ALE_APP_ID': 'ALE_APP_ID',
    'FWPM_CONDITION_ALE_EFFECTIVE_NAME': 'ALE_EFFECTIVE_NAME',
    'FWPM_CONDITION_ALE_NAP_CONTEXT': 'ALE_NAP_CONTEXT',
    'FWPM_CONDITION_ALE_ORIGINAL_APP_ID': 'ALE_ORIGINAL_APP_ID',
    'FWPM_CONDITION_ALE_PACKAGE_ID': 'ALE_PACKAGE_ID',
    'FWPM_CONDITION_ALE_PROMISCUOUS_MODE': 'ALE_PROMISCUOUS_MODE',
    'FWPM_CONDITION_ALE_REMOTE_MACHINE_ID': 'ALE_REMOTE_MACHINE_ID',
    'FWPM_CONDITION_ALE_REMOTE_USER_ID': 'ALE_REMOTE_USER_ID',
    'FWPM_CONDITION_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE': 'ALE_SECURITY_ATTRIBUTE_FQBN_VALUE',
    'FWPM_CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT': 'ALE_SIO_FIREWALL_SYSTEM_PORT',
    'FWPM_CONDITION_ALE_USER_ID': 'ALE_USER_ID',
    'FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX': 'ARRIVAL_INTERFACE_INDEX',
    'FWPM_CONDITION_ARRIVAL_INTERFACE_PROFILE_ID': 'ARRIVAL_INTERFACE_PROFILE_ID',
    'FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE': 'ARRIVAL_INTERFACE_TYPE',
    'FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE': 'ARRIVAL_TUNNEL_TYPE',
    'FWPM_CONDITION_AUTHENTICATION_TYPE': 'AUTHENTICATION_TYPE',
    'FWPM_CONDITION_CLIENT_CERT_KEY_LENGTH': 'CLIENT_CERT_KEY_LENGTH',
    'FWPM_CONDITION_CLIENT_CERT_OID': 'CLIENT_CERT_OID',
    'FWPM_CONDITION_CLIENT_TOKEN': 'CLIENT_TOKEN',
    'FWPM_CONDITION_CURRENT_PROFILE_ID': 'CURRENT_PROFILE_ID',
    'FWPM_CONDITION_DCOM_APP_ID': 'DCOM_APP_ID',
    'FWPM_CONDITION_DESTINATION_INTERFACE_INDEX': 'DESTINATION_INTERFACE_INDEX',
    'FWPM_CONDITION_DESTINATION_SUB_INTERFACE_INDEX': 'DESTINATION_SUB_INTERFACE_INDEX',
    'FWPM_CONDITION_DIRECTION': 'DIRECTION',
    'FWPM_CONDITION_EMBEDDED_LOCAL_ADDRESS_TYPE': 'EMBEDDED_LOCAL_ADDRESS_TYPE',
    'FWPM_CONDITION_EMBEDDED_LOCAL_PORT': 'EMBEDDED_LOCAL_PORT',
    'FWPM_CONDITION_EMBEDDED_PROTOCOL': 'EMBEDDED_PROTOCOL',
    'FWPM_CONDITION_EMBEDDED_REMOTE_ADDRESS': 'EMBEDDED_REMOTE_ADDRESS',
    'FWPM_CONDITION_EMBEDDED_REMOTE_PORT': 'EMBEDDED_REMOTE_PORT',
    'FWPM_CONDITION_ETHER_TYPE': 'ETHER_TYPE',
    'FWPM_CONDITION_FLAGS': 'FLAGS',
    'FWPM_CONDITION_IMAGE_NAME': 'IMAGE_NAME',
    'FWPM_CONDITION_INTERFACE_INDEX': 'INTERFACE_INDEX',
    'FWPM_CONDITION_INTERFACE_MAC_ADDRESS': 'INTERFACE_MAC_ADDRESS',
    'FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH': 'INTERFACE_QUARANTINE_EPOCH',
    'FWPM_CONDITION_INTERFACE_TYPE': 'INTERFACE_TYPE',
    'FWPM_CONDITION_IPSEC_POLICY_KEY': 'IPSEC_POLICY_KEY',
    'FWPM_CONDITION_IPSEC_SECURITY_REALM_ID': 'IPSEC_SECURITY_REALM_ID',
    'FWPM_CONDITION_IP_ARRIVAL_INTERFACE': 'IP_ARRIVAL_INTERFACE',
    'FWPM_CONDITION_IP_DESTINATION_ADDRESS': 'IP_DESTINATION_ADDRESS',
    'FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE': 'IP_DESTINATION_ADDRESS_TYPE',
    'FWPM_CONDITION_IP_DESTINATION_PORT': 'IP_DESTINATION_PORT',
    'FWPM_CONDITION_IP_FORWARD_INTERFACE': 'IP_FORWARD_INTERFACE',
    'FWPM_CONDITION_IP_LOCAL_ADDRESS': 'IP_LOCAL_ADDRESS',
    'FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE': 'IP_LOCAL_ADDRESS_TYPE',
    'FWPM_CONDITION_IP_LOCAL_ADDRESS_V4': 'IP_LOCAL_ADDRESS_V4',
    'FWPM_CONDITION_IP_LOCAL_ADDRESS_V6': 'IP_LOCAL_ADDRESS_V6',
    'FWPM_CONDITION_IP_LOCAL_INTERFACE': 'IP_LOCAL_INTERFACE',
    'FWPM_CONDITION_IP_LOCAL_PORT': 'IP_LOCAL_PORT',
    'FWPM_CONDITION_IP_NEXTHOP_INTERFACE': 'IP_NEXTHOP_INTERFACE',
    'FWPM_CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE': 'IP_PHYSICAL_ARRIVAL_INTERFACE',
    'FWPM_CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE': 'IP_PHYSICAL_NEXTHOP_INTERFACE',
    'FWPM_CONDITION_IP_PROTOCOL': 'IP_PROTOCOL',
    'FWPM_CONDITION_IP_REMOTE_ADDRESS': 'IP_REMOTE_ADDRESS',
    'FWPM_CONDITION_IP_REMOTE_ADDRESS_V4': 'IP_REMOTE_ADDRESS_V4',
    'FWPM_CONDITION_IP_REMOTE_ADDRESS_V6': 'IP_REMOTE_ADDRESS_V6',
    'FWPM_CONDITION_IP_REMOTE_PORT': 'IP_REMOTE_PORT',
    'FWPM_CONDITION_IP_SOURCE_ADDRESS': 'IP_SOURCE_ADDRESS',
    'FWPM_CONDITION_IP_SOURCE_PORT': 'IP_SOURCE_PORT',
    'FWPM_CONDITION_KM_AUTH_NAP_CONTEXT': 'KM_AUTH_NAP_CONTEXT',
    'FWPM_CONDITION_KM_MODE': 'KM_MODE',
    'FWPM_CONDITION_KM_TYPE': 'KM_TYPE',
    'FWPM_CONDITION_L2_FLAGS': 'L2_FLAGS',
    'FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID': 'LOCAL_INTERFACE_PROFILE_ID',
    'FWPM_CONDITION_MAC_DESTINATION_ADDRESS': 'MAC_DESTINATION_ADDRESS',
    'FWPM_CONDITION_MAC_DESTINATION_ADDRESS_TYPE': 'MAC_DESTINATION_ADDRESS_TYPE',
    'FWPM_CONDITION_MAC_LOCAL_ADDRESS': 'MAC_LOCAL_ADDRESS',
    'FWPM_CONDITION_MAC_LOCAL_ADDRESS_TYPE': 'MAC_LOCAL_ADDRESS_TYPE',
    'FWPM_CONDITION_MAC_REMOTE_ADDRESS': 'MAC_REMOTE_ADDRESS',
    'FWPM_CONDITION_MAC_REMOTE_ADDRESS_TYPE': 'MAC_REMOTE_ADDRESS_TYPE',
    'FWPM_CONDITION_MAC_SOURCE_ADDRESS': 'MAC_SOURCE_ADDRESS',
    'FWPM_CONDITION_MAC_SOURCE_ADDRESS_TYPE': 'MAC_SOURCE_ADDRESS_TYPE',
    'FWPM_CONDITION_NDIS_MEDIA_TYPE': 'NDIS_MEDIA_TYPE',
    'FWPM_CONDITION_NDIS_PHYSICAL_MEDIA_TYPE': 'NDIS_PHYSICAL_MEDIA_TYPE',
    'FWPM_CONDITION_NDIS_PORT': 'NDIS_PORT',
    'FWPM_CONDITION_NET_EVENT_TYPE': 'NET_EVENT_TYPE',
    'FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX': 'NEXTHOP_INTERFACE_INDEX',
    'FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID': 'NEXTHOP_INTERFACE_PROFILE_ID',
    'FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE': 'NEXTHOP_INTERFACE_TYPE',
    'FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX': 'NEXTHOP_SUB_INTERFACE_INDEX',
    'FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE': 'NEXTHOP_TUNNEL_TYPE',
    'FWPM_CONDITION_ORIGINAL_ICMP_TYPE': 'ORIGINAL_ICMP_TYPE',
    'FWPM_CONDITION_ORIGINAL_PROFILE_ID': 'ORIGINAL_PROFILE_ID',
    'FWPM_CONDITION_PEER_NAME': 'PEER_NAME',
    'FWPM_CONDITION_PIPE': 'PIPE',
    'FWPM_CONDITION_PROCESS_WITH_RPC_IF_UUID': 'PROCESS_WITH_RPC_IF_UUID',
    'FWPM_CONDITION_QM_MODE': 'QM_MODE',
    'FWPM_CONDITION_REAUTHORIZE_REASON': 'REAUTHORIZE_REASON',
    'FWPM_CONDITION_REMOTE_ID': 'REMOTE_ID',
    'FWPM_CONDITION_REMOTE_USER_TOKEN': 'REMOTE_USER_TOKEN',
    'FWPM_CONDITION_RPC_AUTH_LEVEL': 'RPC_AUTH_LEVEL',
    'FWPM_CONDITION_RPC_AUTH_TYPE': 'RPC_AUTH_TYPE',
    'FWPM_CONDITION_RPC_EP_FLAGS': 'RPC_EP_FLAGS',
    'FWPM_CONDITION_RPC_EP_VALUE': 'RPC_EP_VALUE',
    'FWPM_CONDITION_RPC_IF_FLAG': 'RPC_IF_FLAG',
    'FWPM_CONDITION_RPC_IF_UUID': 'RPC_IF_UUID',
    'FWPM_CONDITION_RPC_IF_VERSION': 'RPC_IF_VERSION',
    'FWPM_CONDITION_RPC_PROTOCOL': 'RPC_PROTOCOL',
    'FWPM_CONDITION_RPC_PROXY_AUTH_TYPE': 'RPC_PROXY_AUTH_TYPE',
    'FWPM_CONDITION_RPC_SERVER_NAME': 'RPC_SERVER_NAME',
    'FWPM_CONDITION_RPC_SERVER_PORT': 'RPC_SERVER_PORT',
    'FWPM_CONDITION_SEC_ENCRYPT_ALGORITHM': 'SEC_ENCRYPT_ALGORITHM',
    'FWPM_CONDITION_SEC_KEY_SIZE': 'SEC_KEY_SIZE',
    'FWPM_CONDITION_SOURCE_INTERFACE_INDEX': 'SOURCE_INTERFACE_INDEX',
    'FWPM_CONDITION_SOURCE_SUB_INTERFACE_INDEX': 'SOURCE_SUB_INTERFACE_INDEX',
    'FWPM_CONDITION_SUB_INTERFACE_INDEX': 'SUB_INTERFACE_INDEX',
    'FWPM_CONDITION_TUNNEL_TYPE': 'TUNNEL_TYPE',
    'FWPM_CONDITION_VLAN_ID': 'VLAN_ID',
    'FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_ID': 'VSWITCH_DESTINATION_INTERFACE_ID',
    'FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE': 'VSWITCH_DESTINATION_INTERFACE_TYPE',
    'FWPM_CONDITION_VSWITCH_DESTINATION_VM_ID': 'VSWITCH_DESTINATION_VM_ID',
    'FWPM_CONDITION_VSWITCH_ID': 'VSWITCH_ID',
    'FWPM_CONDITION_VSWITCH_NETWORK_TYPE': 'VSWITCH_NETWORK_TYPE',
    'FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID': 'VSWITCH_SOURCE_INTERFACE_ID',
    'FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE': 'VSWITCH_SOURCE_INTERFACE_TYPE',
    'FWPM_CONDITION_VSWITCH_SOURCE_VM_ID': 'VSWITCH_SOURCE_VM_ID',
    'FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID': 'VSWITCH_TENANT_NETWORK_ID'
}

match_type_map = {
    'FWP_MATCH_EQUAL': '=',
    'FWP_MATCH_FLAGS_ALL_SET': 'all',
    'FWP_MATCH_FLAGS_NONE_SET': 'none',
    'FWP_MATCH_NOT_EQUAL': '\u2260',
    'FWP_MATCH_RANGE': 'in'
}

action_map = {
    'FWP_ACTION_BLOCK' : 'Block',
    'FWP_ACTION_PERMIT': 'Permit',
    'FWP_ACTION_CALLOUT_INSPECTION': 'Callout inspection',
    'FWP_ACTION_CALLOUT_TERMINATING' :'Callout terminating',
    'FWP_ACTION_CALLOUT_UNKNOWN' : 'Callout unknown'
}

ip_proto_map = {
    '1' : 'ICMP',
    '2' : 'IGMP',
    '6' : 'TCP',
    '17': 'UDP',
    '58': 'IPv6-ICMP'
}
   
#   datetime
#   providers -> dict of providers keyed on providerKey 
#                   {provider_key: {key, name, desc, num_filters}}
#   sublayers -> dict of sublayer keyed on subLayerKey
#                   {sublayer_key: {key, name, desc, weight, num_filters}}
#   layers -> dict of layers keyed on layerKey
#                   {layer_key: {key, id, name, desc, default_sublayer, num_filters, filters[1]}}
#   filters_by_provider -> dict of filters keyed on providerKey
#                   {provider_key: filters[1]}
#   filters_by_sublayer -> dict of filters keyed on sublayerKey
#                   {sublayer_key: filters[1]}
#
#   [1] filters is a list of dicts: 
#                   {name, desc, layer_key, sublayer_key, provider_key, action, weight, condition}
#

root_tag = 'wfpstate'

class WfpState:

    def __init__(self):
        self.datetime = 'Unknown'
        self.providers = {}
        self.sublayers = {}
        self.layers = {}
        self.filters_by_provider = {}
        self.filters_by_sublayer = {}
        self.filters_by_layer = {}

    def _extract_root_node(self, dumpfile):

        # Find the start of the root node
        root_start = dumpfile.find(f'<{root_tag}')
        if root_start == -1:
            raise ValueError(f"Root tag <{root_tag}> not found.")
    
        # Find the end of the root node
        root_end = dumpfile.find(f'</{root_tag}>') + len(f'</{root_tag}>')
        if root_end == -1:
            raise ValueError(f"Closing tag </{root_tag}> not found.")
        
        return dumpfile[root_start:root_end]

    def parse(self, dumpfile):

        # We have encountered wfpstate.xml files with more than one root node.
        # So let's get only the <wfpstate> node.
        data = self._extract_root_node(dumpfile)

        root = untangle.parse(data)
        if hasattr(root, 'wfpstate'):
            node = root.wfpstate
            self.read_datetime(node)
            self.read_providers(node)
            self.read_sublayers(node)
            self.read_layers(node)
        elif hasattr(root, 'wfpdiag'):
            node = root.wfpdiag
            self.read_providers(node)
            self.read_filters(node.filters)
        else:
            raise Exception('Invalid XML file')

    def read_datetime(self, node):
        
        if hasattr(node, 'timeStamp'):
            dt = node.timeStamp.cdata
            try:
                datetime = dateutil.parser.isoparse(dt).astimezone().ctime()
                self.datetime = datetime + ' UTC'
            except Exception as e:
                raise e
                pass
                
    def read_providers(self, node):

        if not hasattr(node, 'providers'):
            raise Exception('<providers> element not found')
            
        providers_node = node.providers
        if not hasattr(providers_node, 'item'):
            raise Exception('No provider <items> found')

        for item in providers_node.item:
            pkey = item.providerKey.cdata
            pname = item.displayData.name.cdata
            pdesc = item.displayData.description.cdata
            self.providers[pkey] = {'key': pkey, 'name': pname, 
                    'desc': pdesc, 'filter_count': 0}

    def read_sublayers(self, node):

        if not hasattr(node, 'subLayers'):
            raise Exception('<subLayers> element not found')
            
        sublayers_node = node.subLayers
        if not hasattr(sublayers_node, 'item'):
            raise Exception('No sublayer <items> found')

        for item in sublayers_node.item:
            slkey = item.subLayerKey.cdata
            slname = item.displayData.name.cdata
            slname = self._fix_sublayer_name(slname, slkey)
            sldesc = item.displayData.description.cdata
            self.sublayers[slkey] = {'key': slkey, 'name': slname, 
                    'desc': sldesc, 'filter_count': 0}

    def read_layers(self, node):

        if not hasattr(node, 'layers'):
            raise Exception('<layers> element not found')
            
        layers_node = node.layers
        if not hasattr(layers_node, 'item'):
            raise Exception('No layer <items> found')

        for item in layers_node.item:
            lkey = item.layer.layerKey.cdata
            lname = item.layer.displayData.name.cdata
            ldesc = item.layer.displayData.description.cdata
            lid = item.layer.layerId.cdata
            ldefault_sublayer_key = item.layer.defaultSubLayerKey.cdata
            
            self.layers[lkey] = {'key': lkey, 'id': lid, 'name': lname, 'desc': ldesc, 
                                    'default_sublayer_key': ldefault_sublayer_key,
                                    'filter_count': 0}  
            if len(item.filters) > 0:
                self.read_filters(item.filters)

    def read_filters(self, filters_node):

        filters = []

        for filter_item in filters_node.item:
            fid = filter_item.filterId.cdata
            fname = filter_item.displayData.name.cdata
            fdesc = filter_item.displayData.description.cdata
            fsublayer_key = filter_item.subLayerKey.cdata
            fprovider_key = filter_item.providerKey.cdata
            if fprovider_key == '':
                fprovider_key = 'Unspecified'
            flayer_key = filter_item.layerKey.cdata
            faction = self._get_action(filter_item.action)
            fweight = self._get_weight(filter_item.weight)
            feffective_weight = self._get_weight(filter_item.effectiveWeight)
            fcondition = self._get_condition(filter_item.filterCondition)
            fdict = {
                'id': fid, 'name': fname, 'desc': fdesc, 'action': faction,
                'weight': fweight, 'effective_weight': feffective_weight, 
                'layer_key': flayer_key, 'sublayer_key': fsublayer_key, 
                'provider_key': fprovider_key, 'condition': fcondition
                }
            filters.append(fdict)

            # Now add this filter to the three filter lists
            # We create the filter list for if one does not already exist
            # for the provider, layer or sublayer.
            if fsublayer_key not in self.filters_by_sublayer.keys():
                self.filters_by_sublayer[fsublayer_key] = []
            self.filters_by_sublayer[fsublayer_key].append(fdict)

            if flayer_key not in self.filters_by_layer.keys():
                self.filters_by_layer[flayer_key] = []
            self.filters_by_layer[flayer_key].append(fdict)

            if fprovider_key not in self.filters_by_provider.keys():
                self.filters_by_provider[fprovider_key] = [] 
            self.filters_by_provider[fprovider_key].append(fdict)

            # Update the filter count for the provider, layer and sublayer.
            # In the event that we do not have a provider, layer or sublayer entry
            # create it.
            if fprovider_key not in self.providers:
                self.providers[fprovider_key] = {'key': fprovider_key, 'name': fprovider_key, 
                    'desc': '', 'filter_count': 0}
            self.providers[fprovider_key]['filter_count'] += 1

            if flayer_key not in self.layers:
                self.layers[flayer_key] = {'key': flayer_key, 'id': '?', 
                    'name': flayer_key, 'desc': '', 'default_sublayer_key': None,
                    'filter_count': 0}
            self.layers[flayer_key]['filter_count'] += 1

            if fsublayer_key not in self.sublayers:
                self.sublayers[fsublayer_key] = {'key': fsublayer_key, 'name': fsublayer_key, 
                    'desc': '', 'filter_count': 0}
            self.sublayers[fsublayer_key]['filter_count'] += 1

        
    def _get_weight(self, weight):

        if weight.type.cdata == 'FWP_EMPTY':
            return 'Not specified'
        elif weight.type.cdata == 'FWP_UINT64':
            return weight.uint64.cdata
        elif weight.type.cdata == 'FWP_UINT8':
            return weight.uint8.cdata
        else:
            return 'Unimplemented'

    def _get_action(self, action):
        return action_map.get(action.type.cdata, 'Unimplemented')

    def _get_condition_value(self, value):

        type = value.type.cdata
        if type == 'FWP_UINT8':
            return value.uint8.cdata
        elif type == 'FWP_UINT16':
            return value.uint16.cdata
        elif type == 'FWP_UINT32':
            return value.uint32.cdata
        elif type == 'FWP_SID':
            return value.sid.cdata
        elif type == 'FWP_SECURITY_DESCRIPTOR_TYPE':
            return value.sd.cdata
        elif type == 'FWP_BYTE_BLOB_TYPE':
            return value.byteBlob.asString.cdata
        elif type == 'FWP_RANGE_TYPE':
            value_low = self._get_condition_value(value.rangeValue.valueLow)
            value_high = self._get_condition_value(value.rangeValue.valueHigh)
            return '({}, {})'.format(value_low, value_high)

    def _get_condition(self, condition):

        if not hasattr(condition, 'item'):
            return 'None'

        s = ''
        for item in condition.item:
            field_str = field_key_map.get(item.fieldKey.cdata, 'Unimplemented')
            match_type_str = match_type_map.get(item.matchType.cdata, '???')
            value_str = self._get_condition_value(item.conditionValue)
            value_str = self._pretty_value(field_str, value_str)
            s = s + '{} {} {}\n'.format(field_str, match_type_str, value_str)

        return s

    # If the sublayer name does not end with 'Sublayer',
    # add a dash and the trailing 6 characters from the key
    def _fix_sublayer_name(self, name, key):

        if not name.endswith('Sublayer'):
            name = name + ' - ' + key[-7:-1]

        return name

    def _pretty_value(self, field, value):

        if field == 'IP_PROTOCOL':
            value = ip_proto_map.get(value, value)
        
        return value