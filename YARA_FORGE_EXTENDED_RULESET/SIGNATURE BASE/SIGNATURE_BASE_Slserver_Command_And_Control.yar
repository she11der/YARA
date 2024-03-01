rule SIGNATURE_BASE_Slserver_Command_And_Control : FILE
{
	meta:
		description = "Searches for the C2 server."
		author = "Matt Brooks, @cmatthewbrooks"
		id = "e4fcda6c-1c9f-5b58-8b07-8d1a0dc4eaf6"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_between-hk-and-burma.yar#L160-L180"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "48a13d27b7dc9a7f3a65752142b2a291e7c3ee93ef67b36aa4202d065e74d80e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$c2 = "safetyssl.security-centers.com"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $c2
}
