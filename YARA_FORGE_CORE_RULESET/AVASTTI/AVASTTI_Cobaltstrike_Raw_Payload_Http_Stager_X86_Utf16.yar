rule AVASTTI_Cobaltstrike_Raw_Payload_Http_Stager_X86_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "c1602e85-5b42-5005-a6d1-7140cb57a3c7"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L458-L478"
		license_url = "N/A"
		logic_hash = "b6e19ee9141aa22d73de6d8145257eba7b3b2bb2edc0996591085c84f242ec87"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }

	condition:
		uint32(@h01+0x013b)==0x07002600 and uint32(@h01+0x0157)==0xa7007900 and uint32(@h01+0x018f)==0xc6009f00 and uint32(@h01+0x01bf)==0x3b002e00 and uint32(@h01+0x01e7)==0x7b001800 and uint32(@h01+0x0219)==0x5d00e200 and uint32(@h01+0x022b)==0x31005e00 and uint32(@h01+0x0249)==0x0b00e000 and uint32(@h01+0x058b)==0x5600a200 and uint32(@h01+0x05b3)==0xe5005300 and uint32(@h01+0x05e9)==0xe2008900
}
