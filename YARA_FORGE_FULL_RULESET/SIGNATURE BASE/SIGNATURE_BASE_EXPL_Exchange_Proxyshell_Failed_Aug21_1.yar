rule SIGNATURE_BASE_EXPL_Exchange_Proxyshell_Failed_Aug21_1 : SCRIPT
{
	meta:
		description = "Detects ProxyShell exploitation attempts in log files"
		author = "Florian Roth (Nextron Systems)"
		id = "9b849042-8918-5322-a35a-2165d4b541d5"
		date = "2021-08-08"
		modified = "2021-08-09"
		reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_proxyshell.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "690e74633ac8671727fe47f6398e536c1b7a4ac469d27d3f7507c75e175716bd"
		score = 50
		quality = 85
		tags = ""

	strings:
		$xr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|mapi\/nspi|EWS\/|X-Rps-CAT)[^\n]{1,400}401 0 0/ nocase ascii
		$xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}401 0 0/ nocase ascii

	condition:
		1 of them
}
