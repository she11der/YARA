rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Ziparchivefile
{
	meta:
		description = "Detects an archive file created by P.A.S. for download operation"
		author = "FR/ANSSI/SDO (modified by Florian Roth)"
		id = "081cc65b-e51c-59fc-a518-cd986e8ee2f7"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sandworm_centreon.yar#L30-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c15e7022f45ec211ba635d6cd31bab16f4fb0d3038fb19d5765e0f751c14a826"
		score = 80
		quality = 85
		tags = ""

	strings:
		$s1 = "Archive created by P.A.S. v."

	condition:
		$s1
}
