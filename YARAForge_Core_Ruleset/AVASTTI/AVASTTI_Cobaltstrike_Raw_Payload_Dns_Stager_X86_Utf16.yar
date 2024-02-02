rule AVASTTI_Cobaltstrike_Raw_Payload_Dns_Stager_X86_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "d148ca33-b233-519d-8ba4-d389de721d15"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L339-L354"
		license_url = "N/A"
		logic_hash = "3519d2af99a159483ba22cd87907bcc87bea1cfc2fb92f5f0334fff1c385ef00"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }

	condition:
		uint32(@h01+0x0149)==0xe5005300 and uint32(@h01+0x017d)==0x07002600 and uint32(@h01+0x0261)==0xc9009c00 and uint32(@h01+0x0333)==0x5600a200 and uint32(@h01+0x034b)==0xe0003500 and uint32(@h01+0x03cb)==0xcc008e00
}