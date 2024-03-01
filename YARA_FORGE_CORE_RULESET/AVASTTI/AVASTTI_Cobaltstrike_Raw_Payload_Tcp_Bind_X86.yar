rule AVASTTI_Cobaltstrike_Raw_Payload_Tcp_Bind_X86
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "ec0a9e27-3650-5393-a93b-2a461b9a0e29"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L59-L96"
		license_url = "N/A"
		logic_hash = "5c56e1f1d85375f19b6085b3d4654d2d1ba38d3dfcfea66707ca8957a6ed7bf8"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }

	condition:
		uint32(@h01+0x009c)==0x0726774c and uint32(@h01+0x00ac)==0x006b8029 and uint32(@h01+0x00bb)==0xe0df0fea and uint32(@h01+0x00d5)==0x6737dbc2 and uint32(@h01+0x00de)==0xff38e9b7 and uint32(@h01+0x00e8)==0xe13bec74 and uint32(@h01+0x00f1)==0x614d6e75 and uint32(@h01+0x00fa)==0x56a2b5f0 and uint32(@h01+0x0107)==0x5fc8d902 and uint32(@h01+0x011a)==0xe553a458 and uint32(@h01+0x0128)==0x5fc8d902 and uint32(@h01+0x013d)==0x614d6e75
}
