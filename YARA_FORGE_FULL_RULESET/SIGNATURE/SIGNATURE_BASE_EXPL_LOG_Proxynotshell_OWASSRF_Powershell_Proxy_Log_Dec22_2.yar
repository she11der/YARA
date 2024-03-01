rule SIGNATURE_BASE_EXPL_LOG_Proxynotshell_OWASSRF_Powershell_Proxy_Log_Dec22_2 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		id = "85722997-fd28-51cf-817e-7a314e284b0b"
		date = "2022-12-22"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_proxynotshell_owassrf_dec22.yar#L24-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "73ce86b7a673719c916666fa06963b774edad5b2cd804994614afd83ea75ecef"
		score = 60
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$sr1 = / \/owa\/[^\/\s]{1,30}(%40|@)[^\/\s\.]{1,30}\.[^\/\s]{2,3}\/powershell / ascii wide
		$sa1 = " 200 " ascii wide
		$sa2 = " POST " ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		all of ($s*) and not 1 of ($fp*)
}
