rule AVASTTI_Cobaltstrike_Raw_Payload_Http_Stager_X64
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "7eeeb2a1-4903-5649-ae30-fd43367ab468"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L234-L263"
		license_url = "N/A"
		logic_hash = "a89a8e25d894bf7e5c4a10e2a14b78a52543e42fb185667db9f9548f52ef58bf"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }

	condition:
		uint32(@h01+0x00e9)==0x0726774c and uint32(@h01+0x0101)==0xa779563a and uint32(@h01+0x0120)==0xc69f8957 and uint32(@h01+0x013f)==0x3b2e55eb and uint32(@h01+0x0163)==0x7b18062d and uint32(@h01+0x0308)==0x56a2b5f0 and uint32(@h01+0x0324)==0xe553a458 and uint32(@h01+0x0342)==0xe2899612
}