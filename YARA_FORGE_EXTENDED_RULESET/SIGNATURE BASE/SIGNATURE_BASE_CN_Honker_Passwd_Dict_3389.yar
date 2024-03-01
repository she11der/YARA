rule SIGNATURE_BASE_CN_Honker_Passwd_Dict_3389 : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file 3389.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "9418f0e5-7bf0-5df3-8857-dea90fae5a54"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L26-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2897e909e48a9f56ce762244c3a3e9319e12362f"
		logic_hash = "2be79fc7388ca12f06577e689944bcfa72ed1e1b6da5a7fa15c8da69a4555a9a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "654321" fullword ascii
		$s1 = "admin123" fullword ascii
		$s2 = "admin123456" fullword ascii
		$s3 = "administrator" fullword ascii
		$s4 = "passwd" fullword ascii
		$s5 = "password" fullword ascii
		$s7 = "12345678" fullword ascii

	condition:
		filesize <1KB and all of them
}
