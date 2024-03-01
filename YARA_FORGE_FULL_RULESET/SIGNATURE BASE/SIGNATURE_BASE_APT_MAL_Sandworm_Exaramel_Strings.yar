rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Strings
{
	meta:
		description = "Detects Strings used by Exaramel malware"
		author = "FR/ANSSI/SDO (composed from 4 saparate rules by Florian Roth)"
		id = "fdc79b87-eb9e-5751-9474-ff653b073165"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sandworm_centreon.yar#L204-L232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9d2790e60184ed973b2735263d0a997f32af0beacc9ea8ef65926fe6507011d5"
		score = 80
		quality = 85
		tags = ""

	strings:
		$persistence1 = "systemd"
		$persistence2 = "upstart"
		$persistence3 = "systemV"
		$persistence4 = "freebsd rc"
		$report1 = "systemdupdate.rep"
		$report2 = "upstartupdate.rep"
		$report3 = "remove.rep"
		$url1 = "/tasks.get/"
		$url2 = "/time.get/"
		$url3 = "/time.set"
		$url4 = "/tasks.report"
		$url5 = "/attachment.get/"
		$url6 = "/auth/app"

	condition:
		(5 of ($url*) and all of ($persistence*)) or ( all of ($persistence*) and all of ($report*)) or (5 of ($url*) and all of ($report*))
}
