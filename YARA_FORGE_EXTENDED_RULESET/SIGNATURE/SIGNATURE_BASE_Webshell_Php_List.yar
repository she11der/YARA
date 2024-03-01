rule SIGNATURE_BASE_Webshell_Php_List
{
	meta:
		description = "Web Shell - file list.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L711-L726"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "922b128ddd90e1dc2f73088956c548ed"
		logic_hash = "007f9307493bca71dcbdcf6ba6c45bf36899e8f636ccbd09c26453cb0aea0847"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "// list.php = Directory & File Listing" fullword
		$s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
		$s9 = "// by: The Dark Raver" fullword

	condition:
		1 of them
}
