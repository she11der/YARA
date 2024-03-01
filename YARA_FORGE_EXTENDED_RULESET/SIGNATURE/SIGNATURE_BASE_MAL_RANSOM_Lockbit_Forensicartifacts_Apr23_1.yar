rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Forensicartifacts_Apr23_1
{
	meta:
		description = "Detects forensic artifacts found in LockBit intrusions"
		author = "Florian Roth"
		id = "e716030c-ee78-51dc-919c-cf59e93da976"
		date = "2023-04-17"
		modified = "2023-12-05"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/mal_lockbit_lnx_macos_apr23.yar#L86-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "81021f8c9aed17c007d7329a598c644a706fa9750818c8974984eefcba8d06c2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "/tmp/locker.log" ascii fullword
		$x2 = "Executable=LockBit/locker_" ascii
		$xc1 = { 54 6F 72 20 42 72 6F 77 73 65 72 20 4C 69 6E 6B 73 3A 0D 0A 68 74 74 70 3A 2F 2F 6C 6F 63 6B 62 69 74 }

	condition:
		1 of ($x*)
}
