#!/usr/bin/env python3
#
# Search for "#restored" and edit below that to control what is restored.
#
import os
import argparse
import requests


from dotenv import load_dotenv
load_dotenv()
load_dotenv(dotenv_path=os.path.join(os.path.expanduser('~'),'.meraki.env'))

parser = argparse.ArgumentParser(description='Restore a Meraki online config from an offline file.')
parser.add_argument('orgName', help='The name of a Meraki organisation')
args = parser.parse_args()

headers = {
	'x-cisco-meraki-api-key': os.getenv('x_cisco_meraki_api_key'),
	'Content-Type': 'application/json'
	}

session = requests.Session()

def get_org_id(orgName):
	try:
		# https://dashboard.meraki.com/api_docs#list-the-organizations-that-the-user-has-privileges-on
		geturl = 'https://api.meraki.com/api/v0/organizations'
		dashboard = session.get(geturl, headers=headers)
		dashboard.raise_for_status()
	except requests.exceptions.HTTPError as err:
		print(err)

	for row in dashboard.json():
		if row['name'] == orgName:
			return row['id']
	raise ValueError('The organization name does not exist')

orgid=get_org_id(args.orgName)


# Edit script below this line to control what is #restored.

# Organisation Dashboard Administrators
# https://dashboard.meraki.com/api_docs#create-a-new-dashboard-administrator
posturl = 'https://api.meraki.com/api/v0/organizations/{0}/admins'.format(str(orgid))
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'administrator123@ikarem.com', 'hasApiKey': False, 'id': '646829496481136255', 'lastActive': 1547850975, 'name': 'adminstrator123', 'networks': [], 'orgAccess': 'full', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'cory.guynn@meraki.com', 'hasApiKey': True, 'id': '646829496481132852', 'lastActive': 1587481379, 'name': 'cory guynn', 'networks': [], 'orgAccess': 'full', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'cory.guynn@meraki.net', 'hasApiKey': True, 'id': '646829496481092187', 'lastActive': 1567666933, 'name': 'Cory Guynn', 'networks': [], 'orgAccess': 'full', 'tags': [{'access': 'full', 'tag': 'Sandbox'}], 'twoFactorAuthEnabled': True}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'daniel.gonzalez@global.ntt', 'hasApiKey': True, 'id': '646829496481183717', 'lastActive': 1587490412, 'name': 'daniel.gonzalez@global.ntt', 'networks': [{'access': 'full', 'id': 'L_646829496481105049'}], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': True}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'dennis.schwarze@swsnet.de', 'hasApiKey': True, 'id': '646829496481184247', 'lastActive': 1587649560, 'name': 'DennisSchwarze9602', 'networks': [{'access': 'full', 'id': 'L_646829496481105071'}], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'devnetmerakiadmin@cisco.com', 'hasApiKey': True, 'id': '646829496481137276', 'lastActive': 1581446042, 'name': 'devnetmerakiadmin', 'networks': [], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'eublack@cisco.com', 'hasApiKey': True, 'id': '646829496481149344', 'lastActive': 1582726638, 'name': 'Eugene Black', 'networks': [], 'orgAccess': 'full', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'unverified', 'email': 'ipletenev@ethcon.de', 'hasApiKey': False, 'id': '646829496481184258', 'lastActive': '', 'name': 'ipletenev', 'networks': [{'access': 'full', 'id': 'L_646829496481105073'}], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'jpontes@gmail.com', 'hasApiKey': True, 'id': '646829496481169719', 'lastActive': 1587158671, 'name': 'DevNet Meraki (DO NOT EDIT)', 'networks': [], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'kiskande@cisco.com', 'hasApiKey': True, 'id': '646829496481169011', 'lastActive': 1587617151, 'name': 'Kareem Iskander', 'networks': [], 'orgAccess': 'full', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'masters@meraki.com', 'hasApiKey': True, 'id': '646829496481109794', 'lastActive': 1587646397, 'name': 'Meraki Master', 'networks': [], 'orgAccess': 'full', 'tags': [{'access': 'full', 'tag': 'Sandbox'}], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'mdenapol@cisco.com', 'hasApiKey': True, 'id': '646829496481139900', 'lastActive': 1587659677, 'name': 'Matt De', 'networks': [], 'orgAccess': 'full', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'meraki_api_docs@cisco.com', 'hasApiKey': True, 'id': '646829496481149826', 'lastActive': 1555619585, 'name': 'Meraki APIDocs', 'networks': [], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'michaeljuergen.moser@sws.de', 'hasApiKey': True, 'id': '646829496481184242', 'lastActive': 1587642259, 'name': 'MichaelJuergen.Moser@sws.de', 'networks': [{'access': 'full', 'id': 'L_646829496481105079'}], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'pablo.verdesoto@udla.edu.ec', 'hasApiKey': True, 'id': '646829496481184240', 'lastActive': 1587658276, 'name': 'pabloverdesoto478233858', 'networks': [{'access': 'full', 'id': 'L_646829496481105081'}], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'patrick.urlberger@sws.de', 'hasApiKey': True, 'id': '646829496481184235', 'lastActive': 1587651235, 'name': 'Patrick.Urlberger@sws.de', 'networks': [{'access': 'full', 'id': 'L_646829496481105064'}], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'robert.jauernek@sws.de', 'hasApiKey': True, 'id': '646829496481184246', 'lastActive': 1587640701, 'name': 'robert.jauernek@sws.de', 'networks': [{'access': 'full', 'id': 'L_646829496481105079'}], 'orgAccess': 'none', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'unverified', 'email': 'sandbox+api@meraki.com', 'hasApiKey': True, 'id': '646829496481146825', 'lastActive': '', 'name': 'sandbox+api@meraki.com', 'networks': [], 'orgAccess': 'full', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'sandbox@meraki.com', 'hasApiKey': True, 'id': '646829496481133023', 'lastActive': 1556527215, 'name': 'Sandbox User', 'networks': [], 'orgAccess': 'full', 'tags': [{'access': 'full', 'tag': 'Sandbox'}], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'stefan.slominski@sws.de', 'hasApiKey': True, 'id': '646829496481184243', 'lastActive': 1587628680, 'name': 'stefan.slominski@sws.de', 'networks': [{'access': 'full', 'id': 'L_646829496481105080'}], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'unverified', 'email': 'tohzono@cisco.com', 'hasApiKey': False, 'id': '646829496481184259', 'lastActive': '', 'name': 'tohzono', 'networks': [{'access': 'full', 'id': 'L_646829496481105090'}], 'orgAccess': 'read-only', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'ulrich.meisl@sws.de', 'hasApiKey': True, 'id': '646829496481184245', 'lastActive': 1587640371, 'name': 'ulrich.meisl@sws.de', 'networks': [{'access': 'full', 'id': 'L_646829496481105079'}], 'orgAccess': 'none', 'tags': [], 'twoFactorAuthEnabled': True}, headers=headers)
dashboard = session.post(posturl, json={'accountStatus': 'ok', 'email': 'ymts.32@gmail.com', 'hasApiKey': True, 'id': '646829496481183466', 'lastActive': 1587648717, 'name': 'adminstrator123', 'networks': [], 'orgAccess': 'full', 'tags': [], 'twoFactorAuthEnabled': False}, headers=headers)

# MX VPN firewall
# https://dashboard.meraki.com/api_docs#mx-vpn-firewall
puturl = 'https://api.meraki.com/api/v0/organizations/{0}/vpnFirewallRules'.format(str(orgid))
dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': True}, headers=headers)

# SNMP Settings
# https://dashboard.meraki.com/api_docs#update-the-snmp-settings-for-an-organization
puturl = 'https://api.meraki.com/api/v0/organizations/{0}/snmp'.format(str(orgid))
try:
	dashboard = session.put(puturl, json={'peerIps': None, 'v2cEnabled': False, 'v3AuthMode': 'SHA', 'v3Enabled': False, 'v3PrivMode': 'AES128'}, headers=headers)
	dashboard.raise_for_status()
except requests.exceptions.HTTPError as err:
	print(err)

# Non Meraki VPN Peers
# https://dashboard.meraki.com/api_docs#update-the-third-party-vpn-peers-for-an-organization
puturl = 'https://api.meraki.com/api/v0/organizations/{0}/thirdPartyVPNPeers'.format(str(orgid))
try:
	dashboard = session.put(puturl, json=[{'ipsecPoliciesPreset': 'default', 'name': 'test', 'networkTags': ['tag1'], 'privateSubnets': ['172.16.13.0/24'], 'publicIp': '1.2.3.4', 'secret': '1234567890'}], headers=headers)
	dashboard.raise_for_status()
except requests.exceptions.HTTPError as err:
	print(err)

# Add Network: DevNet Sandbox Always on READ ONLY
print('Processing network DevNet Sandbox Always on READ ONLY')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481104079', 'name': 'DevNet Sandbox Always on READ ONLY', 'organizationId': '549236', 'productTypes': ['appliance', 'switch', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# MX VLANs
	# https://dashboard.meraki.com/api_docs#enable/disable-vlans-for-the-given-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/vlansEnabledState'.format(str(networkid))
	dashboard = session.put(puturl, json={'enabled': False, 'networkId': 'L_646829496481104079'}, headers=headers)
	# MX cellular firewall
	# https://dashboard.meraki.com/api_docs#mx-cellular-firewall
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/cellularFirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': False}, headers=headers)

	# MX L3 Firewall Rules
	# https://api.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-mx-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogDefaultRule': False}, headers=headers)

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'DNSMB0 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 14', 'number': 13, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 15', 'number': 14, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

except requests.exceptions.HTTPError as err:
	print('Can not add network DevNet Sandbox Always on READ ONLY - it probably already exists')

# Add Network: DNENT2-dxxxzglobal.ntt
print('Processing network DNENT2-dxxxzglobal.ntt')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481105049', 'name': 'DNENT2-dxxxzglobal.ntt', 'organizationId': '549236', 'productTypes': ['appliance', 'camera', 'switch', 'systems manager', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# MX VLANs
	# https://dashboard.meraki.com/api_docs#enable/disable-vlans-for-the-given-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/vlansEnabledState'.format(str(networkid))
	dashboard = session.put(puturl, json={'enabled': False, 'networkId': 'L_646829496481105049'}, headers=headers)
	# MX cellular firewall
	# https://dashboard.meraki.com/api_docs#mx-cellular-firewall
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/cellularFirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': False}, headers=headers)

	# MX L3 Firewall Rules
	# https://api.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-mx-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogDefaultRule': False}, headers=headers)

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'DNENT2 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 14', 'number': 13, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 15', 'number': 14, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

except requests.exceptions.HTTPError as err:
	print('Can not add network DNENT2-dxxxzglobal.ntt - it probably already exists')

# Add Network: DNSMB5-Pxxxxxxxrsws.de
print('Processing network DNSMB5-Pxxxxxxxrsws.de')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481105064', 'name': 'DNSMB5-Pxxxxxxxrsws.de', 'organizationId': '549236', 'productTypes': ['appliance', 'camera', 'switch', 'systems manager', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# MX VLANs
	# https://dashboard.meraki.com/api_docs#enable/disable-vlans-for-the-given-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/vlansEnabledState'.format(str(networkid))
	dashboard = session.put(puturl, json={'enabled': True, 'networkId': 'L_646829496481105064'}, headers=headers)
	# https://dashboard.meraki.com/api_docs#add-a-vlan
	posturl = 'https://api.meraki.com/api/v0/networks/{0}/vlans'.format(str(networkid))
	dashboard = session.post(posturl, json={'applianceIp': '192.168.1.1', 'dhcpBootOptionsEnabled': False, 'dhcpHandling': 'Run a DHCP server', 'dhcpLeaseTime': '1 day', 'dhcpOptions': [], 'dnsNameservers': 'upstream_dns', 'fixedIpAssignments': {}, 'id': 1, 'name': 'Internal', 'networkId': 'L_646829496481105064', 'reservedIpRanges': [], 'subnet': '192.168.1.0/24'}, headers=headers)
	dashboard = session.post(posturl, json={'applianceIp': '192.168.2.1', 'dhcpBootOptionsEnabled': False, 'dhcpHandling': 'Run a DHCP server', 'dhcpLeaseTime': '1 day', 'dhcpOptions': [], 'dnsNameservers': 'upstream_dns', 'fixedIpAssignments': {}, 'id': 2, 'name': 'Guests', 'networkId': 'L_646829496481105064', 'reservedIpRanges': [], 'subnet': '192.168.2.0/24'}, headers=headers)
	dashboard = session.post(posturl, json={'applianceIp': '192.168.3.1', 'dhcpBootOptionsEnabled': False, 'dhcpHandling': 'Run a DHCP server', 'dhcpLeaseTime': '1 day', 'dhcpOptions': [], 'dnsNameservers': 'upstream_dns', 'fixedIpAssignments': {}, 'id': 3, 'name': 'Voice', 'networkId': 'L_646829496481105064', 'reservedIpRanges': [], 'subnet': '192.168.3.0/24'}, headers=headers)

	# MX cellular firewall
	# https://dashboard.meraki.com/api_docs#mx-cellular-firewall
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/cellularFirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': False}, headers=headers)

	# MX L3 Firewall Rules
	# https://api.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-mx-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogDefaultRule': False}, headers=headers)

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'DNSMB5 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 14', 'number': 13, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 15', 'number': 14, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

except requests.exceptions.HTTPError as err:
	print('Can not add network DNSMB5-Pxxxxxxxrsws.de - it probably already exists')

# Add Network: DNSMB1-dxxxxxxxeswsnet.de
print('Processing network DNSMB1-dxxxxxxxeswsnet.de')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481105071', 'name': 'DNSMB1-dxxxxxxxeswsnet.de', 'organizationId': '549236', 'productTypes': ['appliance', 'camera', 'switch', 'systems manager', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# MX VLANs
	# https://dashboard.meraki.com/api_docs#enable/disable-vlans-for-the-given-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/vlansEnabledState'.format(str(networkid))
	dashboard = session.put(puturl, json={'enabled': False, 'networkId': 'L_646829496481105071'}, headers=headers)
	# MX cellular firewall
	# https://dashboard.meraki.com/api_docs#mx-cellular-firewall
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/cellularFirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': False}, headers=headers)

	# MX L3 Firewall Rules
	# https://api.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-mx-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogDefaultRule': False}, headers=headers)

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'DNSMB1 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 14', 'number': 13, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 15', 'number': 14, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

except requests.exceptions.HTTPError as err:
	print('Can not add network DNSMB1-dxxxxxxxeswsnet.de - it probably already exists')

# Add Network: DNSMB3-bxxxxxxtsws.de
print('Processing network DNSMB3-bxxxxxxtsws.de')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481105073', 'name': 'DNSMB3-bxxxxxxtsws.de', 'organizationId': '549236', 'productTypes': ['appliance', 'camera', 'switch', 'systems manager', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# MX VLANs
	# https://dashboard.meraki.com/api_docs#enable/disable-vlans-for-the-given-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/vlansEnabledState'.format(str(networkid))
	dashboard = session.put(puturl, json={'enabled': True, 'networkId': 'L_646829496481105073'}, headers=headers)
	# https://dashboard.meraki.com/api_docs#add-a-vlan
	posturl = 'https://api.meraki.com/api/v0/networks/{0}/vlans'.format(str(networkid))
	dashboard = session.post(posturl, json={'applianceIp': '192.168.128.1', 'dhcpBootOptionsEnabled': False, 'dhcpHandling': 'Run a DHCP server', 'dhcpLeaseTime': '1 day', 'dhcpOptions': [], 'dnsNameservers': 'upstream_dns', 'fixedIpAssignments': {}, 'id': 1, 'name': 'Default', 'networkId': 'L_646829496481105073', 'reservedIpRanges': [], 'subnet': '192.168.128.0/24'}, headers=headers)

	# MX cellular firewall
	# https://dashboard.meraki.com/api_docs#mx-cellular-firewall
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/cellularFirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': False}, headers=headers)

	# MX L3 Firewall Rules
	# https://api.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-mx-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogDefaultRule': False}, headers=headers)

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'DNSMB3 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 14', 'number': 13, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 15', 'number': 14, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

except requests.exceptions.HTTPError as err:
	print('Can not add network DNSMB3-bxxxxxxtsws.de - it probably already exists')

# Add Network: DNSMB2-Mxxxxrsws.de
print('Processing network DNSMB2-Mxxxxrsws.de')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481105079', 'name': 'DNSMB2-Mxxxxrsws.de', 'organizationId': '549236', 'productTypes': ['appliance', 'camera', 'switch', 'systems manager', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# MX VLANs
	# https://dashboard.meraki.com/api_docs#enable/disable-vlans-for-the-given-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/vlansEnabledState'.format(str(networkid))
	dashboard = session.put(puturl, json={'enabled': True, 'networkId': 'L_646829496481105079'}, headers=headers)
	# https://dashboard.meraki.com/api_docs#add-a-vlan
	posturl = 'https://api.meraki.com/api/v0/networks/{0}/vlans'.format(str(networkid))
	dashboard = session.post(posturl, json={'applianceIp': '192.168.128.1', 'dhcpBootOptionsEnabled': False, 'dhcpHandling': 'Run a DHCP server', 'dhcpLeaseTime': '1 day', 'dhcpOptions': [], 'dnsNameservers': 'upstream_dns', 'fixedIpAssignments': {}, 'id': 1, 'name': 'Default', 'networkId': 'L_646829496481105079', 'reservedIpRanges': [], 'subnet': '192.168.128.0/24'}, headers=headers)

	# MX cellular firewall
	# https://dashboard.meraki.com/api_docs#mx-cellular-firewall
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/cellularFirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': False}, headers=headers)

	# MX L3 Firewall Rules
	# https://api.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-mx-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogDefaultRule': False}, headers=headers)

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'DNSMB2 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 14', 'number': 13, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 15', 'number': 14, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

except requests.exceptions.HTTPError as err:
	print('Can not add network DNSMB2-Mxxxxrsws.de - it probably already exists')

# Add Network: DNSMB4-sxxxxisws.de
print('Processing network DNSMB4-sxxxxisws.de')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481105080', 'name': 'DNSMB4-sxxxxisws.de', 'organizationId': '549236', 'productTypes': ['appliance', 'camera', 'switch', 'systems manager', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# MX VLANs
	# https://dashboard.meraki.com/api_docs#enable/disable-vlans-for-the-given-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/vlansEnabledState'.format(str(networkid))
	dashboard = session.put(puturl, json={'enabled': True, 'networkId': 'L_646829496481105080'}, headers=headers)
	# https://dashboard.meraki.com/api_docs#add-a-vlan
	posturl = 'https://api.meraki.com/api/v0/networks/{0}/vlans'.format(str(networkid))
	dashboard = session.post(posturl, json={'applianceIp': '192.168.128.1', 'dhcpBootOptionsEnabled': False, 'dhcpHandling': 'Run a DHCP server', 'dhcpLeaseTime': '1 day', 'dhcpOptions': [], 'dnsNameservers': 'upstream_dns', 'fixedIpAssignments': {}, 'id': 1, 'name': 'Default', 'networkId': 'L_646829496481105080', 'reservedIpRanges': [], 'subnet': '192.168.128.0/24'}, headers=headers)

	# MX cellular firewall
	# https://dashboard.meraki.com/api_docs#mx-cellular-firewall
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/cellularFirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': False}, headers=headers)

	# MX L3 Firewall Rules
	# https://api.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-mx-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogDefaultRule': False}, headers=headers)

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'DNSMB4 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
except requests.exceptions.HTTPError as err:
	print('Can not add network DNSMB4-sxxxxisws.de - it probably already exists')

# Add Network: DNENT3-pxxxxxxoudla.edu.ec
print('Processing network DNENT3-pxxxxxxoudla.edu.ec')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481105081', 'name': 'DNENT3-pxxxxxxoudla.edu.ec', 'organizationId': '549236', 'productTypes': ['appliance', 'camera', 'switch', 'systems manager', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'psk', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'encryptionMode': 'wpa', 'ipAssignmentMode': 'Bridge mode', 'lanIsolationEnabled': False, 'minBitrate': 11, 'name': 'DNENT3 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'psk': 'reAper6472', 'splashPage': 'None', 'ssidAdminAccessible': False, 'useVlanTagging': False, 'visible': True, 'wpaEncryptionMode': 'WPA2 only'}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 14', 'number': 13, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 15', 'number': 14, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

except requests.exceptions.HTTPError as err:
	print('Can not add network DNENT3-pxxxxxxoudla.edu.ec - it probably already exists')

# Add Network: DNENT1-txxxxocisco.com
print('Processing network DNENT1-txxxxocisco.com')
try:
	# https://dashboard.meraki.com/api_docs#create-a-network
	posturl = 'https://api.meraki.com/api/v0/organizations/{0}/networks'.format(str(orgid))
	dashboard = session.post(posturl, json={'disableMyMerakiCom': False, 'disableRemoteStatusPage': True, 'id': 'L_646829496481105090', 'name': 'DNENT1-txxxxocisco.com', 'organizationId': '549236', 'productTypes': ['appliance', 'camera', 'switch', 'systems manager', 'wireless'], 'timeZone': 'America/Los_Angeles', 'type': 'combined'}, headers=headers)
	dashboard.raise_for_status()
	networkid=dashboard.json()['id']

	# MX VLANs
	# https://dashboard.meraki.com/api_docs#enable/disable-vlans-for-the-given-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/vlansEnabledState'.format(str(networkid))
	dashboard = session.put(puturl, json={'enabled': False, 'networkId': 'L_646829496481105090'}, headers=headers)
	# MX cellular firewall
	# https://dashboard.meraki.com/api_docs#mx-cellular-firewall
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/cellularFirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogEnabled': False}, headers=headers)

	# MX L3 Firewall Rules
	# https://api.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-mx-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'syslogDefaultRule': False}, headers=headers)

	# Network - AutoVPN Settings
	# https://dashboard.meraki.com/api_docs#update-the-site-to-site-vpn-settings-of-a-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/siteToSiteVpn'.format(str(networkid))
	dashboard = session.put(puturl, json={'mode': 'none'}, headers=headers)

	# SSIDs
	# https://dashboard.meraki.com/api_docs#update-the-attributes-of-an-ssid
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': True, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'DNENT1 - wireless WiFi', 'number': 0, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/0/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 2', 'number': 1, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/1/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 3', 'number': 2, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/2/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 4', 'number': 3, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/3/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 5', 'number': 4, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/4/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 6', 'number': 5, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/5/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 7', 'number': 6, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/6/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 8', 'number': 7, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/7/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 9', 'number': 8, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/8/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 10', 'number': 9, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/9/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 11', 'number': 10, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/10/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 12', 'number': 11, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/11/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 13', 'number': 12, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/12/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 14', 'number': 13, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/13/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14'.format(str(networkid))
	dashboard = session.put(puturl, json={'authMode': 'open', 'availabilityTags': [], 'availableOnAllAps': True, 'bandSelection': 'Dual band operation', 'enabled': False, 'ipAssignmentMode': 'NAT mode', 'minBitrate': 11, 'name': 'Unconfigured SSID 15', 'number': 14, 'perClientBandwidthLimitDown': 0, 'perClientBandwidthLimitUp': 0, 'radiusAccountingEnabled': None, 'splashPage': 'None', 'ssidAdminAccessible': False, 'visible': True}, headers=headers)
	# MR L3 firewall
	# https://dashboard.meraki.com/api_docs#update-the-l3-firewall-rules-of-an-ssid-on-an-mr-network
	puturl = 'https://api.meraki.com/api/v0/networks/{0}/ssids/14/l3FirewallRules'.format(str(networkid))
	dashboard = session.put(puturl, json={'rules': [], 'allowLanAccess': True}, headers=headers)

except requests.exceptions.HTTPError as err:
	print('Can not add network DNENT1-txxxxocisco.com - it probably already exists')

