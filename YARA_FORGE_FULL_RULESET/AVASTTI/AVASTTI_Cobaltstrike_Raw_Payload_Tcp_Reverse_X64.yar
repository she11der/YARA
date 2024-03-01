rule AVASTTI_Cobaltstrike_Raw_Payload_Tcp_Reverse_X64
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "21151a9c-1d15-514f-b33b-c9eff08463fb"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/01ebdae33c8a83d7848c2a73fbe9f78acc15d46f/CobaltStrike/yara_rules/cs_rules.yar#L166-L195"
		license_url = "N/A"
		logic_hash = "58ae5351bac70ab9530cb033d1f6bb90acb6b66df395d59a55d221ef2a2e5dcf"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }

	condition:
		uint32(@h01+0x0100)==0x0726774c and uint32(@h01+0x0111)==0x006b8029 and uint32(@h01+0x012d)==0xe0df0fea and uint32(@h01+0x0142)==0x6174a599 and uint32(@h01+0x016b)==0x5fc8d902 and uint32(@h01+0x018b)==0xe553a458 and uint32(@h01+0x01a5)==0x5fc8d902 and uint32(@h01+0x01c1)==0x614d6e75
}
