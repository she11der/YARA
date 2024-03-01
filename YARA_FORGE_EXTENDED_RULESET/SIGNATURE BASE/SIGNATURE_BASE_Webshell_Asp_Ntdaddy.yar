rule SIGNATURE_BASE_Webshell_Asp_Ntdaddy
{
	meta:
		description = "Web Shell - file ntdaddy.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L828-L842"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c5e6baa5d140f73b4e16a6cfde671c68"
		logic_hash = "7237eb7233c6affcc1f67a764f704b7d7e1d13f71c64893286c6c99318cc7c3e"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "if  FP  =  \"RefreshFolder\"  or  "
		$s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "

	condition:
		1 of them
}
