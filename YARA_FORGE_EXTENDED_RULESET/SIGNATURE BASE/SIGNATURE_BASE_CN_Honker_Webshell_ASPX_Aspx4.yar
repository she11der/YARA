rule SIGNATURE_BASE_CN_Honker_Webshell_ASPX_Aspx4 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx4.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "4a13c809-48f7-54f7-9ce3-10d6d48104fb"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L511-L527"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "200a8f15ffb6e3af31d28c55588003b5025497eb"
		logic_hash = "0aab8e327b4477cb0b8cd5d4b1e4b52c160180656dad57b0498654da1c8d7a29"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii
		$s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii
		$s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii

	condition:
		filesize <11KB and all of them
}
