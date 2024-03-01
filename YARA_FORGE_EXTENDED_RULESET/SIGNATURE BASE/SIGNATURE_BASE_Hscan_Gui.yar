rule SIGNATURE_BASE_Hscan_Gui : FILE
{
	meta:
		description = "Chinese Hacktool Set - file hscan-gui.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "27f9d2e9-0a62-57ca-9061-c32945c59c7e"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L768-L783"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1885f0b7be87f51c304b39bc04b9423539825c69"
		logic_hash = "c87cfe78324638ac9d35c7fd1e47f24014c470b0892ceceaf394278d9706157b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Hscan.EXE" fullword wide
		$s1 = "RestTool.EXE" fullword ascii
		$s3 = "Hscan Application " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <550KB and all of them
}
