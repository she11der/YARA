rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Configuration_Name_Encrypted
{
	meta:
		description = "Detects the specific name of the configuration file in Exaramel malware as seen in sample e1ff72[...]"
		author = "FR/ANSSI/SDO"
		id = "1c06f5fc-3435-51cd-92fb-17a4ab6b63ad"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_sandworm_centreon.yar#L92-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "f65d59381403534a2c2f39d66c7c62bf1540eafc9aad1ad73de1809e91c42446"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "configtx.json"

	condition:
		all of them
}