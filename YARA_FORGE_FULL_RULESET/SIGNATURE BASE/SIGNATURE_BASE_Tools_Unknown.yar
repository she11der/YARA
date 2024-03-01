rule SIGNATURE_BASE_Tools_Unknown : FILE
{
	meta:
		description = "Chinese Hacktool Set - file unknown.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2cb75a84-506d-5b67-8b1f-b91beb5a99a3"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1237-L1254"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"
		logic_hash = "493bb63d4dd519efbf53a29fa44ef74f0a85943b2d9f49f11e3daa57c6b03d8e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s2 = "GET /ok.asp?id=1__sql__ HTTP/1.1" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve" wide
		$s5 = "Host: 127.0.0.1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2500KB and 4 of them
}
