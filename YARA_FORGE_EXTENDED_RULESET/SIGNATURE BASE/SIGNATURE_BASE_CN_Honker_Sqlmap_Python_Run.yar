rule SIGNATURE_BASE_CN_Honker_Sqlmap_Python_Run : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Run.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "308d929a-0f38-5db4-92c2-2a7bf25bb64f"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1930-L1946"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a51479a1c589f17c77d22f6cf90b97011c33145f"
		logic_hash = "86d53a06e2f71b7ce7785c4c8ac017a4552b40c16d64474db4e22dbe1afd9e52"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = ".\\Run.log" fullword ascii
		$s2 = "[root@Hacker~]# Sqlmap " fullword ascii
		$s3 = "%sSqlmap %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and all of them
}
