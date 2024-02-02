rule AVASTTI_Cobaltstrike_Beacon_Xored_X86
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "d93c20e6-3e01-5132-88a0-63ace507cae9"
		date = "2021-07-08"
		modified = "2021-07-08"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/CobaltStrike/yara_rules/cs_rules.yar#L705-L726"
		license_url = "N/A"
		logic_hash = "1415c8ab5b4ddd6eb0f561b570358f04f967621dfc6274e0380879563b612c27"
		score = 75
		quality = 90
		tags = ""

	strings:
		$h01 = { FC E8??000000 [0-32] EB27 ?? 8B?? 83??04 8B?? 31?? 83??04 ?? 8B?? 31?? 89?? 31?? 83??04 83??04 31?? 39?? 7402 EBEA ?? FF?? E8D4FFFFFF }
		$h02 = { FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? 89??00 31?? 83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }
		$h11 = { 7402 EB(E8|EA) ?? FF?? E8(D0|D4)FFFFFF }

	condition:
		any of ($h0*) and ( uint32be(@h11+12)^ uint32be(@h11+20)==0x4D5AE800 or uint32be(@h11+12)^ uint32be(@h11+20)==0x904D5AE8 or uint32be(@h11+12)^ uint32be(@h11+20)==0x90904D5A or uint32be(@h11+12)^ uint32be(@h11+20)==0x9090904D or uint32be(@h11+12)^ uint32be(@h11+20)==0x90909090)
}