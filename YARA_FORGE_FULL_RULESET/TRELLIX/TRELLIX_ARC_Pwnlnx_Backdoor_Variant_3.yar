import "pe"

rule TRELLIX_ARC_Pwnlnx_Backdoor_Variant_3 : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the backdoor pwnlnx variant"
		author = "Marc Rivero | McAfee ATR Team"
		id = "02ea1eb2-7235-5ed5-86ba-19d52e8fb428"
		date = "2020-04-17"
		modified = "2020-08-14"
		reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_decade_of_RATs.yar#L67-L97"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "08f29e234f0ce3bded1771d702f8b5963b144141727e48b8a0594f58317aac75"
		logic_hash = "8a1405f430ce57810577f65ef43a1425601bf49b5adb4f6f935505427ad9dc94"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Pwnlnx"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$bp = { 7F??4C4602??01??000000000000000002??3E????0000000004??00000000??????000000000000B0??3A??000000000000000040??????????????????????01??000005????????0000000000000000??????0000000000004000000000????????????0000????????????00000000????00000000????0000????0000????A40C??00000000C0??????????????C0??????????????5013??00000000????????????00000000????00000000??????000004??00005801??00000000??????4000000000??????4000000000????000000000000????000000000000??????000000000000070000??????0000C0??????????????C0??????????????C0??????????????28??00000000000078??00000000000008??00000000000051E5??64??000000000000000000000000000000000000000000000000000000000000000000000000000000000000????000000000000??????000010??000001??0000474E5500000000????0000??????000000000000C0????????????????????????0000????84????00000000C8??????0000000025????????0000????374200000000????A56C00000000????????????0000????????????0000????A56C00000000????????????0000??????4200000000????A56C00000000????????????0000????24??00000000????A56C00000000????????????0000????????????0000????A56C00000000????????????0000????83??????0000????A56C00000000????????????0000????5E42000000000000A66C00000000????????????0000??????4200000000????A66C00000000????????????0000????914200000000????A66C00000000????????????0000??????4200000000????A66C00000000????????????0000????????????0000????A66C00000000????????????0000????????????0000????A66C00000000????????????0000??????4200000000????A66C00000000????????????0000??????4200000000??????EC08??4301??????62??0000E8????????4883????C3FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????00000000000000000000000000000000000000000000000031??4989??5E4889??4883????505449C7??????????48C7??????????48C7??????????E8????????F490904883????488B??????????4885??74??FF??4883????C390909090909090909090909090B8????????55482D????????4883????4889??76??B8????????4885??74??5DBF????????FF??660F1F????????????5DC366666666????????????????????BE????????554881??????????48C1????4889??4889??48C1????4801??48D1??74??B8????????4885??74??5DBF????????FF??0F1F??5DC3660F1F??????80????????????75??554889??53BB????????4881??????????4883????488B??????????48C1????4883????4839??73??660F1F??????4883????4889??????????FF????????????488B??????????4839??72??E8????????B8????????4885??74??BF????????E8????????C6????????????4883????5B5DF3??669055B8????????4885??4889??74??BE????????BF????????E8????????BF????????4883????75??5DE9????????6690B8????????4885??74??FF??EB??9090554889??534881??????????89??????????48C7????????????8B????3D????????76??E9????????8B????89??488D??????????8B??????????4889??89??E8????????85??75??E9????????8B????89??488D??????????89??4889??E8????????488D??????????BE????????4889??E8????????4889????4883??????75??E9????????488D??????????488D??????????4889??4889??E8????????85??74??E9????????488B??????????4889????C7????????????488B????89????488B????48C1????89????4883????FF????FF????FF????E8????????4883????89????BE????????488D????E8????????8B??????????BA????????488D????89??E8????????85??75??E9????????8B??????????BA????????488D????89??E8????????85??75??E9????????BE????????488D????E8????????8B????4883????FF????FF????FF????E8????????4883????39??74??E9????????8B????89??48C1????4889??8B????89??4801??4889????488B????488B????BA????????4889??4889??E8????????488B????4889????EB??488B????488D??????????4889??BA????????BE????????4889??E8????????89????83??????7F??EB??8B????488D??????????89??4889??E8????????8B????4863??488D??????????8B??????????4889??89??E8????????85??75??EB??8B????48984801????488B????483B????7C??488B????4889??E8????????B8????????488B????C9C3554889??534881??????????4889??????????E8????????4889??E8????????C7????????????488B??????????8B????89????488B??????????8B??89????488B??????????8B????89????8B????8B????BA????????89??89??E8????????89????83??????75??E9????????488D????BA????????BE????????4889??E8????????C7????????????C7????????????8B????89????4883????FF????FF????FF????E8????????4883????89????488D????BE????????4889??E8????????488D????8B????BA????????4889??89??E8????????85??75??E9????????488D??????????4889??E8????????488D??????????BE????????4889??E8????????488D??????????8B????BA????????4889??89??E8????????85??75??EB??488D????8B????BA????????4889??89??E8????????85??75??EB??488D????BE????????4889??E8????????8B????4883????FF????FF????FF????E8????????4883????39??74??EB??8B????83????74??EB??8B????4883????FF????FF????FF????89??E8????????4883????908B????89??E8????????B8????????488B????C9C3554889??4889????89????C7????????????488B????4889????C7????????????EB??488B????0FB6??8B????99F7????89??48980FB6??????????31??89??488B????88??83??????4883??????8B????3B????7C??488B????5DC3554889??4889????89????488B????4889????C7????????????EB??488B????0FB6??0FB6??????????31??488B????88??83??????4883??????8B????3B????7C??488B????5DC39090554889??534881??????????89??????????48C7????????????48C7????????????48C7????????????8B????89??488D??????????8B??????????4889??89??E8????????85??75??E9????????8B????89??488D??????????89??4889??E8????????488D??????????488D??????????4889??4889??E8????????488D??????????488D??????????4889??BA????????BE????????4889??B8????????E8????????488D??????????4889??E8????????4883????4889??E8????????4889????4883??????75??E9????????488D??????????488B????4889??4889??E8????????488D????488D??????????B9????????BA????????4889??E8????????89????83??????0F8E????????C7????????????E9????????488B????8B????4863??48C1????4801??488B??488D????488D??????????488D??????????4989??4889??BA????????BE????????4889??B8????????E8????????488D??????????488D??????????4889??4889??E8????????85??0F85????????48C7????????????48C7????????????488D??????????4883????4889??E8????????4889??E8????????4989??488B??????????8B??????????25????????89??8B??????????25????????89??488B????8B????4863??48C1????4801??488B??488D????488D??????????415052FF????FF????4189??4189??BA????????BE????????4889??B8????????E8????????4883????488B????4889??E8????????4889??488D?????????? }

	condition:
		uint16(0)==0x457f and filesize <4000KB and all of them
}
