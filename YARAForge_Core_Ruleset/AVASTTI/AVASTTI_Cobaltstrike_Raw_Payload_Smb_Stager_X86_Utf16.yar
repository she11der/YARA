rule AVASTTI_Cobaltstrike_Raw_Payload_Smb_Stager_X86_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "d88e050f-9e6c-5349-b809-ad7dc25a79b9"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L356-L373"
		license_url = "N/A"
		logic_hash = "74c50e1c989167ea6d9309e2b53629c7103484faa809a80e90b7d5c318b2370c"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }

	condition:
		uint32(@h01+0x0145)==0xe5005300 and uint32(@h01+0x018b)==0xd400df00 and uint32(@h01+0x01a7)==0xe2007d00 and uint32(@h01+0x01f3)==0xbb005f00 and uint32(@h01+0x021d)==0xbb005f00 and uint32(@h01+0x0265)==0xfc00dd00 and uint32(@h01+0x0275)==0x52008700 and uint32(@h01+0x0299)==0x5600a200
}