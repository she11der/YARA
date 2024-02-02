rule AVASTTI_Cobaltstrike_Raw_Payload_Https_Stager_X64_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "aa93dd56-9589-5958-9711-ca2f9c763665"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L522-L540"
		license_url = "N/A"
		logic_hash = "dee3eb3353da0179c58a33c3be0af6ad1e6aa9f13e9e6b9821c94f11d209266f"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }

	condition:
		uint32(@h01+0x01d5)==0x07002600 and uint32(@h01+0x0205)==0xa7007900 and uint32(@h01+0x0249)==0xc6009f00 and uint32(@h01+0x0287)==0x3b002e00 and uint32(@h01+0x02db)==0x86009e00 and uint32(@h01+0x030f)==0x7b001800 and uint32(@h01+0x0659)==0x5600a200 and uint32(@h01+0x0691)==0xe5005300 and uint32(@h01+0x06cd)==0xe2008900
}