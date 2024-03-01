rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Configuration_File_Ciphertext
{
	meta:
		description = "Detects contents of the configuration file used by Exaramel (encrypted with key odhyrfjcnfkdtslt, sample e1ff72[...]"
		author = "FR/ANSSI/SDO"
		id = "763dbb17-2bad-5b40-8a7b-b71bc5849cd9"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sandworm_centreon.yar#L120-L132"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9dc7ee5b0a218a2b5be652e137fa090c944c3ddb0f699f521a72896668210813"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = { 6F B6 08 E9 A3 0C 8D 5E DD BE D4 }

	condition:
		all of them
}
