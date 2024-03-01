rule SIGNATURE_BASE_Webshell_Jsp_Reverse_Jsp_Reverse_Jspbd
{
	meta:
		description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L2629-L2647"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cd7409bb6ace3044f3d0bf380133c4fe4a7c0c0309f9d800b397439aa95f81fc"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "8b0e6779f25a17f0ffb3df14122ba594"
		hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
		hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"

	strings:
		$s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
		$s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
		$s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword

	condition:
		all of them
}
