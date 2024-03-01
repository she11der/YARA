rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Configuration_File_Plaintext
{
	meta:
		description = "Detects contents of the configuration file used by Exaramel (plaintext)"
		author = "FR/ANSSI/SDO"
		id = "6f0d834b-e6c8-59e6-bf9a-b4fd9c0b2297"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_sandworm_centreon.yar#L106-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "1739f94a44db7cb92f9efb8c235c88b5c25f002f213ee846b6b69bd212291992"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = /{"Hosts":\[".{10,512}"\],"Proxy":".{0,512}","Version":".{1,32}","Guid":"/

	condition:
		all of them
}
