rule SIGNATURE_BASE_Shelltools_G0T_Root_Fport
{
	meta:
		description = "Webshells Auto-generated - file Fport.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "664e7b19-4d0b-5062-97d2-0eb34869024d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7998-L8010"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "dbb75488aa2fa22ba6950aead1ef30d5"
		logic_hash = "b9dc66e249c0577839cc3748f129c343d2ccb7327b92a2a67e4467782d10a25e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "Copyright 2000 by Foundstone, Inc."
		$s5 = "You must have administrator privileges to run fport - exiting..."

	condition:
		all of them
}
