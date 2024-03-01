rule SIGNATURE_BASE_CN_Honker_Hxdef100 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file hxdef100.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3b931752-85ae-52d0-9deb-1a1b03b39e32"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L879-L895"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "bf30ccc565ac40073b867d4c7f5c33c6bc1920d6"
		logic_hash = "49f15482104297f0c57713712a7add49d58007afeefd11151dc5749b755860ba"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "BACKDOORSHELL" fullword ascii
		$s15 = "%tmpdir%" fullword ascii
		$s16 = "%cmddir%" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
