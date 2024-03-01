rule SIGNATURE_BASE_Webshell_Redirect
{
	meta:
		description = "Web Shell - file redirect.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1307-L1320"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "97da83c6e3efbba98df270cc70beb8f8"
		logic_hash = "b16026623fe7802db9823ad4a3dab051747eea6bd41ce72a0c8c6757bfa2c6f7"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "

	condition:
		all of them
}
