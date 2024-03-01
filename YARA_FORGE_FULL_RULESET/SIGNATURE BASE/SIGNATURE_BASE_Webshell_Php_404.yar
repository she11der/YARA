rule SIGNATURE_BASE_Webshell_PHP_404
{
	meta:
		description = "Web Shell - file 404.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1452-L1465"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "078c55ac475ab9e028f94f879f548bca"
		logic_hash = "b0524ecddf990048e3e40f471c24075c0e87654c6fe40f17dc3ff43743402e24"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"

	condition:
		all of them
}
