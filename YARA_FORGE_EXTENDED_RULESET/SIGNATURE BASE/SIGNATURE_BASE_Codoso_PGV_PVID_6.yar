rule SIGNATURE_BASE_Codoso_PGV_PVID_6 : FILE
{
	meta:
		description = "Detects Codoso APT PGV_PVID Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "6d1d8490-fdcb-5263-ae00-0b436e822fc3"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_codoso.yar#L115-L129"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4b16f6e8414d4192d0286b273b254fa1bd633f5d3d07ceebd03dfdfc32d0f17f"
		logic_hash = "0907274bd6c97b7d7b2913e42aa748c92012aeeb32196ddcbcd30332f4e95ac9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "rundll32 \"%s\",%s" fullword ascii
		$s1 = "/c ping 127.%d & del \"%s\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <6000KB and all of them
}
