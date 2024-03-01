rule SIGNATURE_BASE_Sql1433_Start : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Start.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "89bc249d-dba0-5196-b081-ddbd029ae6c8"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktool_scripts.yar#L127-L145"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "bd4be10f4c3a982647b2da1a8fb2e19de34eaf01"
		logic_hash = "b7dfc2b04e838fa3a71487287a50e183443eb62b69cd23494294f231b43baf2f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s2 = "start creck.bat" fullword ascii
		$s3 = "del s1.txt" fullword ascii
		$s4 = "del Result.txt" fullword ascii
		$s5 = "del s.TXT" fullword ascii
		$s6 = "mode con cols=48 lines=20" fullword ascii

	condition:
		filesize <1KB and 2 of them
}
