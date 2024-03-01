rule SIGNATURE_BASE_Hytop_Devpack_Server
{
	meta:
		description = "Webshells Auto-generated - file server.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "0e4fee1b-8a16-5738-9600-fa965f8c84c2"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7451-L7462"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1d38526a215df13c7373da4635541b43"
		logic_hash = "66b8513a532f64af535c948da28674795ae6495b9844165c3b039bf61c25eb46"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<!-- PageServer Below -->"

	condition:
		all of them
}
