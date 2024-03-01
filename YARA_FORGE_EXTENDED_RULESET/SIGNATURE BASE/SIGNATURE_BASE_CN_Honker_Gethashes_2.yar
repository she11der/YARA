rule SIGNATURE_BASE_CN_Honker_Gethashes_2 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "31117d2e-caf1-58c9-8525-b40b73097928"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1807-L1823"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "35ae9ccba8d607d8c19a065cf553070c54b091d8"
		logic_hash = "778fde2c59d4523142c0ac5b5c953c9eedbbf3c00b406541c00c1aa1f1a9cc58"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "GetHashes.exe <SAM registry file> [System key file]" fullword ascii
		$s2 = "GetHashes.exe $Local" fullword ascii
		$s3 = "The system key doesn't match SAM registry file!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 2 of them
}
