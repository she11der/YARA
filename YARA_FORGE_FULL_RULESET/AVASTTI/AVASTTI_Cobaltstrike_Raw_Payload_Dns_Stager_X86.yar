rule AVASTTI_Cobaltstrike_Raw_Payload_Dns_Stager_X86
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "817c4a72-7be1-5a58-987d-fe203d7778ea"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/01ebdae33c8a83d7848c2a73fbe9f78acc15d46f/CobaltStrike/yara_rules/cs_rules.yar#L1-L26"
		license_url = "N/A"
		logic_hash = "d447fac16f0a712b1c264bc83b4cf2e56e5e98b369617799b981cd75b37c3511"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }

	condition:
		uint32(@h01+0x00a3)==0xe553a458 and uint32(@h01+0x00bd)==0x0726774c and uint32(@h01+0x012f)==0xc99cc96a and uint32(@h01+0x0198)==0x56a2b5f0 and uint32(@h01+0x01a4)==0xe035f044 and uint32(@h01+0x01e4)==0xcc8e00f4
}
