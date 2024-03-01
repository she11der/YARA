rule SIGNATURE_BASE_Gsecdump_Password_Dump_File : FILE
{
	meta:
		description = "Detects a gsecdump output file"
		author = "Florian Roth (Nextron Systems)"
		id = "c7c8ab61-f728-5eb2-a5e3-b3dd84980870"
		date = "2018-03-06"
		modified = "2023-12-05"
		reference = "https://t.co/OLIj1yVJ4m"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/generic_dumps.yar#L32-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "483ad5217cbc065bd2f791c473b9a2455fddc4e0123268a8d37c64d92dd78c43"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Administrator(current):500:" ascii

	condition:
		uint32be(0)==0x41646d69 and filesize <3000 and $x1 at 0
}
