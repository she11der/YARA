rule AVASTTI_Cobaltstrike_Raw_Payload_Http_Stager_X64_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "78672e3b-6f76-573a-8a9a-610334baa389"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L480-L497"
		license_url = "N/A"
		logic_hash = "f88378749f0da0c66d66b917eeb11a56f083bb487c19c22a230dee4f50e1e309"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }

	condition:
		uint32(@h01+0x01d5)==0x07002600 and uint32(@h01+0x0205)==0xa7007900 and uint32(@h01+0x0243)==0xc6009f00 and uint32(@h01+0x0281)==0x3b002e00 and uint32(@h01+0x02c9)==0x7b001800 and uint32(@h01+0x0613)==0x5600a200 and uint32(@h01+0x064b)==0xe5005300 and uint32(@h01+0x0687)==0xe2008900
}