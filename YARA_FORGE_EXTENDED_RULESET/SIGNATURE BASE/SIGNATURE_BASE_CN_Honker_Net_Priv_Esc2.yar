rule SIGNATURE_BASE_CN_Honker_Net_Priv_Esc2 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file net-priv-esc2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b4fa3129-57a3-55ee-8ca6-ecbcc135184e"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L256-L271"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4851e0088ad38ac5b3b1c75302a73698437f7f17"
		logic_hash = "53cf3d984bc82428eb0a6ee416bcd5429718a1d615ce1c1ba399cda42268d26c"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Usage:%s username password" fullword ascii
		$s2 = "<www.darkst.com>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <17KB and all of them
}
