rule SIGNATURE_BASE_Txt_Aspx : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspx.jpg"
		author = "Florian Roth (Nextron Systems)"
		id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L665-L681"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ce24e277746c317d887139a0d71dd250bfb0ed58"
		logic_hash = "43c386bfa88db77801b0494d6a5e4406688f957ffedeb4d2ecdd244549dec708"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
		$s2 = "Process[] p=Process.GetProcesses();" fullword ascii
		$s3 = "Copyright &copy; 2009 Bin" ascii
		$s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii

	condition:
		filesize <100KB and all of them
}
