rule SIGNATURE_BASE_Sbin_Squid : FILE
{
	meta:
		description = "Chinese Hacktool Set - file squid.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "e7302e90-d072-599b-a8f2-bf1f21a84de9"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktool_scripts.yar#L92-L108"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8b795a8085c3e6f3d764ebcfe6d59e26fdb91969"
		logic_hash = "c440bcfda55f926354ea5e462fe1e6a0e9e9585bb1c1539c0aa0588405a46105"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "del /s /f /q" fullword ascii
		$s1 = "squid.exe -z" fullword ascii
		$s2 = "net start Squid" fullword ascii
		$s3 = "net stop Squid" fullword ascii

	condition:
		filesize <1KB and all of them
}
