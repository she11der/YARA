rule SIGNATURE_BASE_Webshell_Jsp_Up
{
	meta:
		description = "Web Shell - file up.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L406-L419"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "515a5dd86fe48f673b72422cccf5a585"
		logic_hash = "77c8121d000c45e44717689dec535fde7c9722005d1e4ff40d0b84abcf289f47"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword

	condition:
		all of them
}
