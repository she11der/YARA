rule SIGNATURE_BASE_CN_Honker__D_Injection_V2_32_D_Injection_V2_32_D_Injection_V2_32 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files D_injection_V2.32.exe, D_injection_V2.32.exe, D_injection_V2.32.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "79e9cd97-c070-5109-a0a0-bc88eea0dc37"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2467-L2488"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5c318c670b3aedf66da1c6444df7d630d2263e88527facfcf75d76dd974e7d31"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		hash1 = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		hash2 = "3a000b976c79585f62f40f7999ef9bdd326a9513"

	strings:
		$s1 = "upfile.asp " fullword ascii
		$s2 = "[wscript.shell]" fullword ascii
		$s3 = "XP_CMDSHELL" fullword ascii
		$s4 = "[XP_CMDSHELL]" fullword ascii
		$s5 = "http://d99net.3322.org" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and 4 of them
}
