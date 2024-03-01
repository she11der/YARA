rule SIGNATURE_BASE_Slserver_Mutex : FILE
{
	meta:
		description = "Searches for the mutex."
		author = "Matt Brooks, @cmatthewbrooks"
		id = "decdefd0-fe20-5adf-9d8c-0e2b954481a0"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_between-hk-and-burma.yar#L138-L158"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9bf3c6c93e77424463e3fb6f9f4d58e80254866462fe1287293b0a357737da20"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$mutex = "M&GX^DSF&DA@F"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $mutex
}
