rule SIGNATURE_BASE_PP_CN_APT_Zerot_9 : FILE
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "e1c32993-409c-5a62-8239-cff99fb83a7f"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_cn_pp_zerot.yar#L149-L163"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "af4b85ef01c4fa21a2506369f3bc0f8eff6e95a4cfd494e1ea11a44d75bb024e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a685cf4dca6a58213e67d041bba637dca9cb3ea6bb9ad3eae3ba85229118bce0"

	strings:
		$x1 = "nflogger.dll" fullword ascii
		$s7 = "Zlh.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
