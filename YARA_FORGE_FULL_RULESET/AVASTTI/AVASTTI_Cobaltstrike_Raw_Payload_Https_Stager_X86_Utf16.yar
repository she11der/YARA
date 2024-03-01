rule AVASTTI_Cobaltstrike_Raw_Payload_Https_Stager_X86_Utf16
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "dcd3e5c8-7626-5a78-9f90-7a8e67311d90"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/01ebdae33c8a83d7848c2a73fbe9f78acc15d46f/CobaltStrike/yara_rules/cs_rules.yar#L499-L520"
		license_url = "N/A"
		logic_hash = "5003ebd545182bb105cdcaaac2105a92cdd99a0178c24eb5ae2888232897aeb5"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }

	condition:
		uint32(@h01+0x013b)==0x07002600 and uint32(@h01+0x0161)==0xa7007900 and uint32(@h01+0x0199)==0xc6009f00 and uint32(@h01+0x01d1)==0x3b002e00 and uint32(@h01+0x0203)==0x86009e00 and uint32(@h01+0x0223)==0x7b001800 and uint32(@h01+0x0255)==0x5d00e200 and uint32(@h01+0x0267)==0x31005e00 and uint32(@h01+0x0285)==0x0b00e000 and uint32(@h01+0x05d5)==0x5600a200 and uint32(@h01+0x05fd)==0xe5005300 and uint32(@h01+0x0633)==0xe2008900
}
