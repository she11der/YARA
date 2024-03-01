rule SIGNATURE_BASE_COZY_FANCY_BEAR_Hunt : FILE
{
	meta:
		description = "Detects Cozy Bear / Fancy Bear C2 Server IPs"
		author = "Florian Roth (Nextron Systems)"
		id = "e81b4368-7383-5a48-a89a-f91b9306326e"
		date = "2016-06-14"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fancybear_dnc.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9009f181eeecce0ae322ba24335426399cf4484dfc9b7ea6905fb163b4bf0a25"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "185.100.84.134" ascii wide fullword
		$s2 = "58.49.58.58" ascii wide fullword
		$s3 = "218.1.98.203" ascii wide fullword
		$s4 = "187.33.33.8" ascii wide fullword
		$s5 = "185.86.148.227" ascii wide fullword
		$s6 = "45.32.129.185" ascii wide fullword
		$s7 = "23.227.196.217" ascii wide fullword

	condition:
		uint16(0)==0x5a4d and 1 of them
}
