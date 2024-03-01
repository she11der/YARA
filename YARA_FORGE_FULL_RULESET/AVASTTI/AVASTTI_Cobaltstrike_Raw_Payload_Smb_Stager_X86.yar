rule AVASTTI_Cobaltstrike_Raw_Payload_Smb_Stager_X86
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "29911a14-08ea-54de-9c07-630c6516bd49"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/01ebdae33c8a83d7848c2a73fbe9f78acc15d46f/CobaltStrike/yara_rules/cs_rules.yar#L28-L57"
		license_url = "N/A"
		logic_hash = "7459bcb0353f114a869aa61adc0229197ca9a1cfce0741dc227fabbeea2afba9"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }

	condition:
		uint32(@h01+0x00a1)==0xe553a458 and uint32(@h01+0x00c4)==0xd4df7045 and uint32(@h01+0x00d2)==0xe27d6f28 and uint32(@h01+0x00f8)==0xbb5f9ead and uint32(@h01+0x010d)==0xbb5f9ead and uint32(@h01+0x0131)==0xfcddfac0 and uint32(@h01+0x0139)==0x528796c6 and uint32(@h01+0x014b)==0x56a2b5f0
}
