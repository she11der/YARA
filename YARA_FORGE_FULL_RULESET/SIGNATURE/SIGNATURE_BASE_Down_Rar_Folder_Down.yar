rule SIGNATURE_BASE_Down_Rar_Folder_Down
{
	meta:
		description = "Webshells Auto-generated - file down.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "4e0a0e03-4f01-5b58-807c-0934cdda77ab"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8878-L8889"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "db47d7a12b3584a2e340567178886e71"
		logic_hash = "bc666d6333d49a2b01553e1946fc304195193b9be92e26805474e64da61455da"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"

	condition:
		all of them
}
