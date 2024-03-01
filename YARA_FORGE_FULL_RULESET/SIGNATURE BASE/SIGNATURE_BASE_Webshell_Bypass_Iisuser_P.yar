rule SIGNATURE_BASE_Webshell_Bypass_Iisuser_P
{
	meta:
		description = "Web shells - generated from file bypass-iisuser-p.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3282-L3295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "924d294400a64fa888a79316fb3ccd90"
		logic_hash = "60d0609291e5def26ce949c903ac767db4157b4f9cf4eee315c69ee7a8d8e77b"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"

	condition:
		all of them
}
