rule SIGNATURE_BASE_Slserver_Campaign_Code : FILE
{
	meta:
		description = "Searches for the related campaign code."
		author = "Matt Brooks, @cmatthewbrooks"
		id = "672f506e-0cc1-5b09-873b-c3d206486bac"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_between-hk-and-burma.yar#L182-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fbf53678399b0e14eae6f1bb6594b2aa665f76f10388e492bec2f9101a4dd4b1"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$campaign = "wthkdoc0106"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $campaign
}
