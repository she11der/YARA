rule SIGNATURE_BASE_HKTL_Unknown_Feb19_1
{
	meta:
		description = "Detetcs a tool used in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "bdcadc4b-8881-5dc7-b203-4e79cbc850ed"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_aus_parl_compromise.yar#L154-L172"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "231c771ed24106a8daf352a0df1bc2db43ebd8d1108d7fa1162d03d40e738d46"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "not a valid timeout format!" ascii wide fullword
		$x2 = "host can not be empty!" ascii wide fullword
		$x3 = "not a valid port format!" ascii wide fullword
		$x4 = "{0} - {1} TTL={2} time={3}" ascii wide fullword
		$x5 = "ping count is not a correct format!" ascii wide fullword
		$s1 = "The result is too large,program store to '{0}'.Please download it manully." fullword ascii wide
		$s2 = "C:\\Windows\\temp\\" ascii wide

	condition:
		1 of ($x*) or 2 of them
}
