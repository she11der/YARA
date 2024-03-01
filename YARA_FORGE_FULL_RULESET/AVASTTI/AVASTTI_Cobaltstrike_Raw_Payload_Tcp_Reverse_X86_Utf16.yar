rule AVASTTI_Cobaltstrike_Raw_Payload_Tcp_Reverse_X86_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "321c1f3f-b7fc-5408-b460-6aa4423d381c"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/01ebdae33c8a83d7848c2a73fbe9f78acc15d46f/CobaltStrike/yara_rules/cs_rules.yar#L420-L437"
		license_url = "N/A"
		logic_hash = "5495405ef3a54c960cf27147dce0d25cb298fee84a99415b59bc548c4f64a1e6"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }

	condition:
		uint32(@h01+0x013b)==0x07002600 and uint32(@h01+0x015b)==0x00006b00 and uint32(@h01+0x0179)==0xe000df00 and uint32(@h01+0x01ad)==0x61007400 and uint32(@h01+0x01cd)==0x5600a200 and uint32(@h01+0x01e7)==0x5f00c800 and uint32(@h01+0x020d)==0xe5005300 and uint32(@h01+0x0229)==0x5f00c800
}
