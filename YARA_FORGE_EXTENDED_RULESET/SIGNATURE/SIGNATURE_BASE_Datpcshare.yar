rule SIGNATURE_BASE_Datpcshare : FILE
{
	meta:
		description = "Chinese Hacktool Set - file datPcShare.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1bf44c0d-6aa7-5486-baee-c17d3e82403f"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1526-L1542"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"
		logic_hash = "15297a8019192371032fc11b966d1a89d951c176da6d64e80ca5a201f55341c0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "PcShare.EXE" fullword wide
		$s2 = "MZKERNEL32.DLL" fullword ascii
		$s3 = "PcShare" fullword wide
		$s4 = "QQ:4564405" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
