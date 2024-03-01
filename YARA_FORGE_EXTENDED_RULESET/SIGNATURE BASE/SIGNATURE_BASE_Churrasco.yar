rule SIGNATURE_BASE_Churrasco : FILE
{
	meta:
		description = "Chinese Hacktool Set - file churrasco.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "99cb5a7a-85c1-57f5-b5b6-f0b1092e1e06"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1664-L1681"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"
		logic_hash = "36ca7c8d1579eeb571c182c033c312b3b231313b8950c1e24eeb3df793b004c4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Done, command should have ran as SYSTEM!" ascii
		$s2 = "Running command with SYSTEM Token..." ascii
		$s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
		$s4 = "Found SYSTEM token 0x%x" ascii
		$s5 = "Thread not impersonating, looking for another thread..." ascii

	condition:
		uint16(0)==0x5a4d and filesize <150KB and 2 of them
}
