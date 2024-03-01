rule SIGNATURE_BASE_Webshell_Jsp_Guige
{
	meta:
		description = "Web Shell - file guige.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L477-L490"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2c9f2dafa06332957127e2c713aacdd2"
		logic_hash = "9d71095b5c709dfdd8b5fcebcaa4493d9c93e841e85cda2e2255e0c15ea83659"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"

	condition:
		all of them
}
