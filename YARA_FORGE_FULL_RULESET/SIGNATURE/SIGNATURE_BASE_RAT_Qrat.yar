rule SIGNATURE_BASE_RAT_Qrat
{
	meta:
		description = "Detects QRAT"
		author = "Kevin Breen @KevTheHermit"
		id = "2ee645a3-1e01-513c-a636-098e445adeca"
		date = "2015-01-08"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L753-L773"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6d404153ca64b547885e4e4581205f5fc20faf86e8ab18002c5deedca2487225"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a0 = "e-data"
		$a1 = "quaverse/crypter"
		$a2 = "Qrypt.class"
		$a3 = "Jarizer.class"
		$a4 = "URLConnection.class"

	condition:
		4 of them
}
