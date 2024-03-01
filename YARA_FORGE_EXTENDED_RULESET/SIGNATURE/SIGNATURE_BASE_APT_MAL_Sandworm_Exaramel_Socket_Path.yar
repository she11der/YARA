rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Socket_Path
{
	meta:
		description = "Detects path of the unix socket created to prevent concurrent executions in Exaramel malware"
		author = "FR/ANSSI/SDO"
		id = "3aab84c9-9748-5d11-9cd7-efa9151036cf"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sandworm_centreon.yar#L134-L146"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8c049b5a7b508ca0f160d166f3c726e4a23a2c5b3105d075d7bf7a301a1c58f6"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "/tmp/.applocktx"

	condition:
		all of them
}
