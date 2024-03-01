rule SIGNATURE_BASE_Webshell_ASP_Zehir
{
	meta:
		description = "Web Shell - file zehir.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1250-L1263"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0061d800aee63ccaf41d2d62ec15985d"
		logic_hash = "90920258017cf189da128dce477e71f0040bc66aefa6f018f64db64d22f60ae5"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"

	condition:
		all of them
}
