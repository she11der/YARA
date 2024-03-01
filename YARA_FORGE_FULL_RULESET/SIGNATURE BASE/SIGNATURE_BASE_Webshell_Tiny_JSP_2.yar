rule SIGNATURE_BASE_Webshell_Tiny_JSP_2 : FILE
{
	meta:
		description = "Detects a tiny webshell - chine chopper"
		author = "Florian Roth (Nextron Systems)"
		id = "b628c4f9-eb07-592d-834a-5c94e41987da"
		date = "2015-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9710-L9722"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6fd514df9d53293a8cfd4b9c807f993558e39979592aa221f18cd76079c00fb7"
		score = 100
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<%eval(Request(" nocase

	condition:
		uint16(0)==0x253c and filesize <40 and all of them
}
