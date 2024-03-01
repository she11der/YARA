rule SIGNATURE_BASE_CN_Honker_Ms10048_X64 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms10048-x64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b65b0bad-d74c-5e7a-a613-69ef80585c23"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L828-L843"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
		logic_hash = "49addce6bef7588bf7683836a54bec6a2a646ecc3f7547083174d2255454cdf0"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[ ] Creating evil window" fullword ascii
		$s2 = "[+] Set to %d exploit half succeeded" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <125KB and all of them
}
