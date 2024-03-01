rule SIGNATURE_BASE_Webshell_Zacosmall
{
	meta:
		description = "Web Shell - file zacosmall.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1279-L1292"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
		logic_hash = "739d58e3ab6712c703e0cb0e0070afec3376844b77ed081a5d12407cabb62319"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"

	condition:
		all of them
}
