rule SIGNATURE_BASE_CN_Honker_Hookmsgina : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Hookmsgina.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "77813637-ec9f-599c-90c9-be1dd93b45f7"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2036-L2053"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f4d9b329b45fbcf6a3b9f29f2633d5d3d76c9f9d"
		logic_hash = "1e268624a5f8df200ef1a03ce167f38feda59836a864e17297473ba223c5895a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\\\.\\pipe\\WinlogonHack" fullword ascii
		$s2 = "%s?host=%s&domain=%s&user=%s&pass=%s&port=%u" fullword ascii
		$s3 = "Global\\WinlogonHack_Load%u" fullword ascii
		$s4 = "Hookmsgina.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
