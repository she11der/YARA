rule SIGNATURE_BASE_Webshell_Asp_01
{
	meta:
		description = "Web Shell - file 01.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L594-L607"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "61a687b0bea0ef97224c7bd2df118b87"
		logic_hash = "e057800013a9a8f4c3ecbe4e27c14e904700548e6ad9dc1f00313c7a3de7fd2d"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%eval request(\"pass\")%>" fullword

	condition:
		all of them
}
