rule SIGNATURE_BASE_Slserver_Unknown_String : FILE
{
	meta:
		description = "Searches for a unique string."
		author = "Matt Brooks, @cmatthewbrooks"
		id = "00341604-480f-59aa-9c18-009e7b53928e"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_between-hk-and-burma.yar#L204-L224"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "18d3bb236282c506c161949883722da1cb0af6dd87bf5cb3d4a5b3d90f4a7db0"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$string = "test-b7fa835a39"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $string
}
