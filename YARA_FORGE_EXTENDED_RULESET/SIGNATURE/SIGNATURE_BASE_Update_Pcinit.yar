rule SIGNATURE_BASE_Update_Pcinit : FILE
{
	meta:
		description = "Chinese Hacktool Set - file PcInit.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "71c34049-97a2-5611-a081-21a85f8631d9"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L296-L314"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"
		logic_hash = "ee4b17dfb0d70464669edab1b7610efa607adb2918306ae6c50130024008a169"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\svchost.exe" ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Global\\ps%08x" fullword ascii
		$s4 = "drivers\\" ascii
		$s5 = "StrStrA" fullword ascii
		$s6 = "StrToIntA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of them
}
