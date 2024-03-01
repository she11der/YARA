rule SIGNATURE_BASE_EXPL_LOG_Proxynotshell_OWASSRF_Powershell_Proxy_Log_Dec22_3 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		id = "76dd786e-daaa-5cd9-8e3e-50d9eab7f9d2"
		date = "2022-12-22"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_proxynotshell_owassrf_dec22.yar#L47-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "607d3743a46e0c5000b9c7847dd89f5d7ccf29f4f1af9bce6870d7738f071f5c"
		score = 60
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$sa1 = " POST /powershell - 444 " ascii wide
		$sa2 = " POST /Powershell - 444 " ascii wide
		$sb1 = " - 200 0 0 2" ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		1 of ($sa*) and $sb1 and not 1 of ($fp*)
}
