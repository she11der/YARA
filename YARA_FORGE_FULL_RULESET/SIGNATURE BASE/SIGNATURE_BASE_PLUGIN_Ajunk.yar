rule SIGNATURE_BASE_PLUGIN_Ajunk : FILE
{
	meta:
		description = "Chinese Hacktool Set - file AJunk.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "af92d01d-5e24-52f7-934a-0ad102fc7a93"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1256-L1271"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"
		logic_hash = "e37504aab506138493ddc0979697502819824ef00c7931599130fafb5d84a7a9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "AJunk.dll" fullword ascii
		$s2 = "AJunk.DLL" fullword wide
		$s3 = "AJunk Dynamic Link Library" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <560KB and all of them
}
