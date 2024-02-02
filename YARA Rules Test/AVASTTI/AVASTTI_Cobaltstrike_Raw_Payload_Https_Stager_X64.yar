rule AVASTTI_Cobaltstrike_Raw_Payload_Https_Stager_X64
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "5f9c7426-63be-5049-91fc-63b5c29618bd"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L306-L337"
		license_url = "N/A"
		logic_hash = "cb36d75efcd0e76bf96793863d1aa5145237ec3ce5c7195e679f2e1019d5bbab"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }

	condition:
		uint32(@h01+0x00e9)==0x0726774c and uint32(@h01+0x0101)==0xa779563a and uint32(@h01+0x0123)==0xc69f8957 and uint32(@h01+0x0142)==0x3b2e55eb and uint32(@h01+0x016c)==0x869e4675 and uint32(@h01+0x0186)==0x7b18062d and uint32(@h01+0x032b)==0x56a2b5f0 and uint32(@h01+0x0347)==0xe553a458 and uint32(@h01+0x0365)==0xe2899612
}