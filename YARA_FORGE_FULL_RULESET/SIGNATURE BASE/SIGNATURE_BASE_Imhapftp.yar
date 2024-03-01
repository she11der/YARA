rule SIGNATURE_BASE_Imhapftp
{
	meta:
		description = "Webshells Auto-generated - file iMHaPFtp.php"
		author = "Florian Roth (Nextron Systems)"
		id = "c810c630-ce08-5059-ad49-f65b244f4d19"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7328-L7339"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "12911b73bc6a5d313b494102abcf5c57"
		logic_hash = "c24bb80a0ae4284b4303450e9103c5dda30c41b41f323641ac1175461f741ced"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"

	condition:
		all of them
}
