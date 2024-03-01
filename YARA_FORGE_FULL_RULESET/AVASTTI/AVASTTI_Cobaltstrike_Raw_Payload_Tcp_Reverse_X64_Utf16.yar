rule AVASTTI_Cobaltstrike_Raw_Payload_Tcp_Reverse_X64_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "1cc2494c-1f39-5a72-93af-c267eaf768fe"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/01ebdae33c8a83d7848c2a73fbe9f78acc15d46f/CobaltStrike/yara_rules/cs_rules.yar#L439-L456"
		license_url = "N/A"
		logic_hash = "d7e8fe5d2e07b7a85fadaa432bf345231ac4ddac5458167431403ddfe05467fc"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }

	condition:
		uint32(@h01+0x0203)==0x07002600 and uint32(@h01+0x0225)==0x00006b00 and uint32(@h01+0x025d)==0xe000df00 and uint32(@h01+0x0287)==0x61007400 and uint32(@h01+0x02d9)==0x5f00c800 and uint32(@h01+0x0319)==0xe5005300 and uint32(@h01+0x034d)==0x5f00c800 and uint32(@h01+0x0385)==0x61004d00
}
