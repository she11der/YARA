rule AVASTTI_Cobaltstrike_Raw_Payload_Tcp_Bind_X86_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "7f17985d-b245-5e95-9b35-af669aafc263"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/01ebdae33c8a83d7848c2a73fbe9f78acc15d46f/CobaltStrike/yara_rules/cs_rules.yar#L375-L396"
		license_url = "N/A"
		logic_hash = "2c5ac98ffbea197d14cd6e508729885b5f86adbace0a6d978664908e070965cf"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }

	condition:
		uint32(@h01+0x013b)==0x07002600 and uint32(@h01+0x015b)==0x00006b00 and uint32(@h01+0x0179)==0xe000df00 and uint32(@h01+0x01ad)==0x67003700 and uint32(@h01+0x01bf)==0xff003800 and uint32(@h01+0x01d3)==0xe1003b00 and uint32(@h01+0x01e5)==0x61004d00 and uint32(@h01+0x01f7)==0x5600a200 and uint32(@h01+0x0211)==0x5f00c800 and uint32(@h01+0x0237)==0xe5005300 and uint32(@h01+0x0253)==0x5f00c800 and uint32(@h01+0x027d)==0x61004d00
}
