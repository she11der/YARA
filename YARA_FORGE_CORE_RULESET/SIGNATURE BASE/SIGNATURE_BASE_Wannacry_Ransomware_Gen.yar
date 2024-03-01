rule SIGNATURE_BASE_Wannacry_Ransomware_Gen : FILE
{
	meta:
		description = "Detects WannaCry Ransomware"
		author = "Florian Roth (Nextron Systems) (based on rule by US CERT)"
		id = "d28d3d76-9c24-5476-9a0c-936c17477d6a"
		date = "2017-05-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-132A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_wannacry.yar#L48-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8f81c918dc1e2c8ef2e334ae504f88b10aef9e54a64486061d45296d2d738aab"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
		hash2 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
		hash3 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"

	strings:
		$s1 = "__TREEID__PLACEHOLDER__" ascii
		$s2 = "__USERID__PLACEHOLDER__" ascii
		$s3 = "Windows for Workgroups 3.1a" fullword ascii
		$s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
		$s5 = "LANMAN1.0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and all of them
}
