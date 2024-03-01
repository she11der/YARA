rule AVASTTI_Cobaltstrike_Raw_Payload_Tcp_Bind_X64
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "3575408a-3309-5723-a49a-9c2088d43de9"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L98-L133"
		license_url = "N/A"
		logic_hash = "a803a9c76142ccadda5f5c8f6abf78ac9a60523576edf62f4a1600556f4b6261"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }

	condition:
		uint32(@h01+0x0100)==0x0726774c and uint32(@h01+0x0111)==0x006b8029 and uint32(@h01+0x012d)==0xe0df0fea and uint32(@h01+0x0142)==0x6737dbc2 and uint32(@h01+0x0150)==0xff38e9b7 and uint32(@h01+0x0161)==0xe13bec74 and uint32(@h01+0x016f)==0x614d6e75 and uint32(@h01+0x0198)==0x5fc8d902 and uint32(@h01+0x01b8)==0xe553a458 and uint32(@h01+0x01d2)==0x5fc8d902 and uint32(@h01+0x01ee)==0x614d6e75
}
