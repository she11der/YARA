rule AVASTTI_Cobaltstrike_Beacon_Xored_X64
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "15be610a-7552-5473-8da2-639220313783"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L728-L746"
		license_url = "N/A"
		logic_hash = "11e6c8be28325d42f24fb5bb43c0b5fd35990a46857bae7c9940262a33c02a8c"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC 4883E4F0 EB33 5D 8B4500 4883C504 8B4D00 31C1 4883C504 55 8B5500 31C2 895500 31D0 4883C504 83E904 31D2 39D1 7402 EBE7 58 FC 4883E4F0 FFD0 E8C8FFFFFF }
		$h11 = { FC 4883E4F0 FFD0 E8C8FFFFFF }

	condition:
		$h01 and ( uint32be(@h11+12)^ uint32be(@h11+20)==0x4D5A4152 or uint32be(@h11+12)^ uint32be(@h11+20)==0x904D5A41 or uint32be(@h11+12)^ uint32be(@h11+20)==0x90904D5A or uint32be(@h11+12)^ uint32be(@h11+20)==0x9090904D or uint32be(@h11+12)^ uint32be(@h11+20)==0x90909090)
}
