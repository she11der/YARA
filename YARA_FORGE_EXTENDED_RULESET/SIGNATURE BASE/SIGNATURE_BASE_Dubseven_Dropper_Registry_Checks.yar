rule SIGNATURE_BASE_Dubseven_Dropper_Registry_Checks : FILE
{
	meta:
		description = "Searches for registry keys checked for by the dropper"
		author = "Matt Brooks, @cmatthewbrooks"
		id = "8369cdbb-53b8-5dc5-9181-fd49747042a7"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_between-hk-and-burma.yar#L31-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "813ff641a4213cf9d56013768e284e7f622a223c6c4f585c3bbbcf69fc03723c"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$reg1 = "SOFTWARE\\360Safe\\Liveup"
		$reg2 = "Software\\360safe"
		$reg3 = "SOFTWARE\\kingsoft\\Antivirus"
		$reg4 = "SOFTWARE\\Avira\\Avira Destop"
		$reg5 = "SOFTWARE\\rising\\RAV"
		$reg6 = "SOFTWARE\\JiangMin"
		$reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and all of ($reg*)
}
