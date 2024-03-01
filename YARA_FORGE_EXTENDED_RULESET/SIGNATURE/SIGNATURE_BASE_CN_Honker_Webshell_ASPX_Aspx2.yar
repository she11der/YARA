rule SIGNATURE_BASE_CN_Honker_Webshell_ASPX_Aspx2 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx2.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "0da59fde-2214-5677-943f-05b8da4fd9d4"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L706-L723"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "95db7a60f4a9245ffd04c4d9724c2745da55e9fd"
		logic_hash = "7af90992bc3f708d877dcd5841c0d132793e41a0796607907084516d955b3ae0"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii
		$s1 = "<head runat=\"server\">" fullword ascii
		$s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii
		$s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <9KB and all of them
}
