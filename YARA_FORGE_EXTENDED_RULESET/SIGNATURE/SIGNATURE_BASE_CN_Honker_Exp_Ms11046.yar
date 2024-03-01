rule SIGNATURE_BASE_CN_Honker_Exp_Ms11046 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11046.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "aafb45f4-3b42-5c8f-8c25-40fd01217e9d"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1392-L1409"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
		logic_hash = "0496e5c062c1a248b118c2f6009c95bfddf753e5491529d4ec43cfaf1ea0c0c5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "[*] Token system command" fullword ascii
		$s1 = "[*] command add user 90sec 90sec" fullword ascii
		$s2 = "[*] Add to Administrators success" fullword ascii
		$s3 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
