rule SIGNATURE_BASE_Webshell_Jsp_K81
{
	meta:
		description = "Web Shell - file k81.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1235-L1249"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "41efc5c71b6885add9c1d516371bd6af"
		logic_hash = "f9c6b5bec9313c6fd059055fa18332675838419bba3348bb852b50806f26ccb2"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
		$s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword

	condition:
		1 of them
}
