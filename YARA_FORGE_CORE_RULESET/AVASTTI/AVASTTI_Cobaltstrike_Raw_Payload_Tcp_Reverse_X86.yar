rule AVASTTI_Cobaltstrike_Raw_Payload_Tcp_Reverse_X86
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "ac824189-614d-5bff-9bbb-a4244cace563"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L135-L164"
		license_url = "N/A"
		logic_hash = "c20de49c3225a7aed8460d0e3cc3bce715c8746fb4313a2faf9da3c8d1d87387"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }

	condition:
		uint32(@h01+0x009c)==0x0726774c and uint32(@h01+0x00ac)==0x006b8029 and uint32(@h01+0x00bb)==0xe0df0fea and uint32(@h01+0x00d5)==0x6174a599 and uint32(@h01+0x00e5)==0x56a2b5f0 and uint32(@h01+0x00f2)==0x5fc8d902 and uint32(@h01+0x0105)==0xe553a458 and uint32(@h01+0x0113)==0x5fc8d902
}
