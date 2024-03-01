rule SIGNATURE_BASE_EXPL_Log4J_Callbackdomain_Iocs_Dec21_1 : CVE_2021_44228
{
	meta:
		description = "Detects IOCs found in Log4Shell incidents that indicate exploitation attempts of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "474afa96-1758-587e-8cab-41c5205e245e"
		date = "2021-12-12"
		modified = "2023-12-05"
		reference = "https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_log4j_cve_2021_44228.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8d5e60f91b715242c6f8ee806ab81d3e296ce1467cf2d065b053f33e3ae00f14"
		score = 60
		quality = 35
		tags = "CVE-2021-44228"

	strings:
		$xr1 = /\b(ldap|rmi):\/\/([a-z0-9\.]{1,16}\.bingsearchlib\.com|[a-z0-9\.]{1,40}\.interact\.sh|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]{2,5}\/([aZ]|ua|Exploit|callback|[0-9]{10}|http443useragent|http80useragent)\b/

	condition:
		1 of them
}
