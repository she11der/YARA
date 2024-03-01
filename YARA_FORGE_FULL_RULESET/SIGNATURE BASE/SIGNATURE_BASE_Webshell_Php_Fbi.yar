rule SIGNATURE_BASE_Webshell_Php_Fbi
{
	meta:
		description = "Web Shell - file fbi.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L636-L649"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1fb32f8e58c8deb168c06297a04a21f1"
		logic_hash = "de8584ae83ee3e23f4ce00ccd73f75b4568d6a4544af45b83784a9a0c34d42e3"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo"

	condition:
		all of them
}
