rule SIGNATURE_BASE_CN_Honker_Webshell_ASPX_Aspx : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "4a13c809-48f7-54f7-9ce3-10d6d48104fb"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L529-L546"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8378619b2a7d446477946eabaa1e6744dec651c1"
		logic_hash = "b59684633fd72bd1804a96850a8b358db98c169415b6e65fe3ecfb4d9fde72d0"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
		$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
		$s2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID" ascii
		$s3 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+" ascii

	condition:
		filesize <353KB and 2 of them
}
