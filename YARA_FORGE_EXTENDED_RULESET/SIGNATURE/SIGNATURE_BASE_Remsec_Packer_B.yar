rule SIGNATURE_BASE_Remsec_Packer_B
{
	meta:
		description = "Detects malware from Symantec's Strider APT report"
		author = "Symantec"
		id = "18e7f84e-27f2-532d-9ead-0db6e9e6c0b2"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_strider.yara#L78-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9c63b5934d60b59a33364ef56c913220e59b9798a682a7f97e6755270adf4e4b"
		score = 80
		quality = 85
		tags = ""

	strings:
		$code = { 48 8B 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 05 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 89 44 24 ?? 48 8D ( 45 ?? | 84 24 ?? ?? 00 00 ) ( 44 88 6? 24 ?? | C6 44 24 ?? 00 ) 48 89 44 24 ?? 48 8D ( 45 ?? | 84 24 ?? ?? 00 00 ) C7 44 24 ?? 0? 00 00 00 2B ?8 48 89 ?C 24 ?? 44 89 6? 24 ?? 83 C? 08 89 ?C 24 ?? ( FF | 41 FF ) D? ( 05 | 8D 88 ) 00 00 00 3A }

	condition:
		all of them
}
