rule SIGNATURE_BASE_RAT_Adzok
{
	meta:
		description = "Detects Adzok RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "93807f85-ae4e-5fd2-9010-ed2cf6f57f38"
		date = "2015-01-05"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Adzok"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L24-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ee3291a4396ba6cb3c5e22229de4f5e45714b29bfeac1c56bde6d038a9d25458"
		score = 75
		quality = 85
		tags = ""
		Versions = "Free 1.0.0.3,"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = "config.xmlPK"
		$a2 = "key.classPK"
		$a3 = "svd$1.classPK"
		$a4 = "svd$2.classPK"
		$a5 = "Mensaje.classPK"
		$a6 = "inic$ShutdownHook.class"
		$a7 = "Uninstall.jarPK"
		$a8 = "resources/icono.pngPK"

	condition:
		7 of ($a*)
}
