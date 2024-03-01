rule SIGNATURE_BASE_SFXRAR_Acrotray : FILE
{
	meta:
		description = "Most likely a malicious file acrotray in SFX RAR / CloudDuke APT 5442.1.exe, 5442.2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1566fb75-d3a8-5e22-b05b-3a2f37374f31"
		date = "2015-07-22"
		modified = "2023-12-05"
		reference = "https://www.f-secure.com/weblog/archives/00002822.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cloudduke.yar#L42-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3b318ab2854eb7614dd1a42d3971a96d1d485d5cce552336ad3a7f39886ba710"
		score = 70
		quality = 85
		tags = "FILE"
		super_rule = 1
		hash1 = "51e713c7247f978f5836133dd0b8f9fb229e6594763adda59951556e1df5ee57"
		hash2 = "5d695ff02202808805da942e484caa7c1dc68e6d9c3d77dc383cfa0617e61e48"
		hash3 = "56531cc133e7a760b238aadc5b7a622cd11c835a3e6b78079d825d417fb02198"

	strings:
		$s1 = "winrarsfxmappingfile.tmp" fullword wide
		$s2 = "GETPASSWORD1" fullword wide
		$s3 = "acrotray.exe" fullword ascii
		$s4 = "CryptUnprotectMemory failed" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2449KB and all of them
}
