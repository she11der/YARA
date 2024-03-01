rule SIGNATURE_BASE_Sphinx_Moth_Kerberos64 : FILE
{
	meta:
		description = "sphinx moth threat group file kerberos64.dll"
		author = "Kudelski Security - Nagravision SA (modified by Florian Roth)"
		id = "5a2487e4-cda4-5d45-9351-edd2b69c460a"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "www.kudelskisecurity.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sphinx_moth.yar#L87-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "13aeb72fcd0f5fd6e73464a90787c756c50569f9eae48945e4ff90d8f9073585"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "KERBEROS64.dll" fullword ascii
		$s1 = "zeSecurityDescriptor" fullword ascii
		$s2 = "SpGetInfo" fullword ascii
		$s3 = "SpShutdown" fullword ascii
		$op0 = { 75 05 e8 6a c7 ff ff 48 8b 1d 47 d6 00 00 33 ff }
		$op1 = { 48 89 05 0c 2b 01 00 c7 05 e2 29 01 00 09 04 00 }
		$op2 = { 48 8d 3d e3 ee 00 00 ba 58 }

	condition:
		uint16(0)==0x5a4d and filesize <406KB and all of ($s*) and 1 of ($op*)
}
