rule SIGNATURE_BASE_Maindll_Mutex : FILE
{
	meta:
		description = "Matches on the maindll mutex"
		author = "Matt Brooks, @cmatthewbrooks"
		id = "7a89dae3-9e03-5803-9729-78e6e65e91d3"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_between-hk-and-burma.yar#L83-L103"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8d3311164104198e02e700c2e9a5293e55d75d63b39c75c4e375b7f35eb5fde4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$mutex = "h31415927tttt"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $mutex
}
