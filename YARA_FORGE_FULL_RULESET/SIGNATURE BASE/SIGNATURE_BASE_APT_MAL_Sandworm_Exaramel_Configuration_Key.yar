rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Configuration_Key
{
	meta:
		description = "Detects the encryption key for the configuration file used by Exaramel malware as seen in sample e1ff72[...]"
		author = "FR/ANSSI/SDO"
		id = "8078de62-3dd2-5ee0-8bda-f508e4013144"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sandworm_centreon.yar#L78-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "056503a2c240a641cd2292a30ab1090e3a358cb4d57dca83b836ecb1bc62ed6b"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "odhyrfjcnfkdtslt"

	condition:
		all of them
}
