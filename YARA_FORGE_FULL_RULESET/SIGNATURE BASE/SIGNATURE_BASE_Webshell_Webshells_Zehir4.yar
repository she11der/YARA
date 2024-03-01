rule SIGNATURE_BASE_Webshell_Webshells_Zehir4
{
	meta:
		description = "Webshells Github Archive - file zehir4"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6664-L6677"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "788928ae87551f286d189e163e55410acbb90a64"
		logic_hash = "36b6940ffecd9be190cce62252ec7d87f1c0bc0d19b4442df63f4404eb316364"
		score = 55
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
		$s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"

	condition:
		1 of them
}
