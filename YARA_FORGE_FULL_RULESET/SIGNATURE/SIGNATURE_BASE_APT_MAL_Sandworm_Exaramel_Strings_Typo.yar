rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Strings_Typo
{
	meta:
		description = "Detects misc strings in Exaramel malware with typos"
		author = "FR/ANSSI/SDO"
		id = "fdc79b87-eb9e-5751-9474-ff653b073165"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sandworm_centreon.yar#L187-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "65e6de743eb9fc742674c7e54eef8a376963a6fd4380bacd03fe6f92d4235920"
		score = 80
		quality = 85
		tags = ""

	strings:
		$typo1 = "/sbin/init | awk "
		$typo2 = "Syslog service for monitoring \n"
		$typo3 = "Error.Can't update app! Not enough update archive."
		$typo4 = ":\"metod\""

	condition:
		3 of ($typo*)
}
