rule SIGNATURE_BASE_EXPL_LOG_CVE_2021_27055_Exchange_Forensic_Artefacts : LOG
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Zach Stanford - @svch0st, Florian Roth"
		id = "8b0110a9-fd03-5f7d-bdd8-03ff48bcac68"
		date = "2021-03-10"
		modified = "2021-03-15"
		reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hafnium_log_sigs.yar#L67-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "131ff0ce189dfeace0922000b0d15dfb5a1270bee8fba8e4d66aa75b1d3f864f"
		score = 65
		quality = 60
		tags = ""

	strings:
		$x1 = "ServerInfo~" ascii wide
		$sr1 = /\/ecp\/[0-9a-zA-Z]{1,3}\.js/ ascii wide
		$s1 = "/ecp/auth/w.js" ascii wide
		$s2 = "/owa/auth/w.js" ascii wide
		$s3 = "/owa/auth/x.js" ascii wide
		$s4 = "/ecp/main.css" ascii wide
		$s5 = "/ecp/default.flt" ascii wide
		$s6 = "/owa/auth/Current/themes/resources/logon.css" ascii wide

	condition:
		$x1 and 1 of ($s*)
}
