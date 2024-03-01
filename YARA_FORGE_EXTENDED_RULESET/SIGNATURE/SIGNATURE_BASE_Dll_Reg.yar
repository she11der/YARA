rule SIGNATURE_BASE_Dll_Reg : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Reg.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "97c0d9ff-6a12-57e3-8219-6c1843a03a29"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktool_scripts.yar#L76-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cb8a92fe256a3e5b869f9564ecd1aa9c5c886e3f"
		logic_hash = "db2032d5689f9fcfc446d5ebe8a6d28c6dbd8bcd1d93769ec969d76f8add4f9d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "copy PacketX.dll C:\\windows\\system32\\PacketX.dll" fullword ascii
		$s1 = "regsvr32.exe C:\\windows\\system32\\PacketX.dll" fullword ascii

	condition:
		filesize <1KB and all of them
}
