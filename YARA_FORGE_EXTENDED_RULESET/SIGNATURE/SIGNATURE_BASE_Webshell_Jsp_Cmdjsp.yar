rule SIGNATURE_BASE_Webshell_Jsp_Cmdjsp
{
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1321-L1334"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b815611cc39f17f05a73444d699341d4"
		logic_hash = "b4822e47a27c598be746ac71bf9b60dafe08d50c83a2dfee5e40ea384fcff21a"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword

	condition:
		all of them
}
