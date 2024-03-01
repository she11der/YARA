rule SIGNATURE_BASE_CN_Honker_Webshell_ASPX_Shell_Shell : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file shell.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "8fbcae22-07b7-5afe-9f15-06e2f426b5ca"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L842-L857"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1816006827d16ed73cefdd2f11bd4c47c8af43e4"
		logic_hash = "ac22d89353b4316289bf6c6e13332ac401f4b57f6c29b71861cb48359c1e55f9"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii
		$s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii

	condition:
		filesize <1KB and all of them
}
