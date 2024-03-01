rule SIGNATURE_BASE_CVE_2017_11882_RTF : CVE_2017_11882 FILE
{
	meta:
		description = "Detects suspicious Microsoft Equation OLE contents as used in CVE-2017-11882"
		author = "Florian Roth (Nextron Systems)"
		id = "400689ff-e856-5cbf-a7fa-93f6a8d8dbb9"
		date = "2018-02-13"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/exploit_cve_2017_11882.yar#L58-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "729fa8215a24990371369158d4582cc0ba9387eb0e7221860bf7216046c447cb"
		score = 60
		quality = 85
		tags = "CVE-2017-11882, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "4d534854412e4558452068747470"
		$x2 = "6d736874612e6578652068747470"
		$x3 = "6d736874612068747470"
		$x4 = "4d534854412068747470"
		$s1 = "4d6963726f736f6674204571756174696f6e20332e30" ascii
		$s2 = "4500710075006100740069006f006e0020004e00610074006900760065" ascii
		$s3 = "2e687461000000000000000000000000000000000000000000000"

	condition:
		( uint32be(0)==0x7B5C7274 or uint32be(0)==0x7B5C2A5C) and filesize <300KB and (1 of ($x*) or 2 of them )
}
