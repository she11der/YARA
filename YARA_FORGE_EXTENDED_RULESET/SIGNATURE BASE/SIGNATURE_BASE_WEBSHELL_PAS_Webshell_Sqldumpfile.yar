rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Sqldumpfile
{
	meta:
		description = "Detects SQL dump file created by P.A.S. webshell"
		author = "FR/ANSSI/SDO"
		id = "4c26feeb-3031-5c91-9eeb-4b5fe9702e39"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sandworm_centreon.yar#L64-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c34abcada22fdf462fd66cc2da18ab9e54215defc6f7a7a95b5a80d1155a2ffe"
		score = 90
		quality = 85
		tags = ""

	strings:
		$ = "-- [ SQL Dump created by P.A.S. ] --"

	condition:
		1 of them
}
