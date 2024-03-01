rule AVASTTI_Cobaltstrike_Raw_Payload_Tcp_Bind_X64_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "bd52fb44-379a-5c82-9c7c-b10c8080b53f"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L398-L418"
		license_url = "N/A"
		logic_hash = "cdd8e0c9bdaf8d7662a118964abdea8eaea6c0e17fe1f20a80497c0c43d496d6"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }

	condition:
		uint32(@h01+0x0203)==0x07002600 and uint32(@h01+0x0225)==0x00006b00 and uint32(@h01+0x025d)==0xe000df00 and uint32(@h01+0x0287)==0x67003700 and uint32(@h01+0x02a3)==0xff003800 and uint32(@h01+0x02c5)==0xe1003b00 and uint32(@h01+0x02e1)==0x61004d00 and uint32(@h01+0x0333)==0x5f00c800 and uint32(@h01+0x0373)==0xe5005300 and uint32(@h01+0x03a7)==0x5f00c800 and uint32(@h01+0x03df)==0x61004d00
}
