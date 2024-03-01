rule SIGNATURE_BASE_Webshell_Caterpillar_ASPX
{
	meta:
		description = "Volatile Cedar Webshell - from file caterpillar.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "9af48c64-3768-5765-8245-38df000598a7"
		date = "2015-04-03"
		modified = "2023-12-05"
		reference = "http://goo.gl/emons5"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_volatile_cedar.yar#L106-L126"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9df2e4a25052136d6e622273f917bd15df410869a8cf3075c773a14ea62a2a55"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "af4c99208fb92dc42bc98c4f96c3536ec8f3fe56"

	strings:
		$s0 = "Dim objNewRequest As WebRequest = HttpWebRequest.Create(sURL)" fullword
		$s1 = "command = \"ipconfig /all\"" fullword
		$s3 = "For Each xfile In mydir.GetFiles()" fullword
		$s6 = "Dim oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
		$s10 = "recResult = adoConn.Execute(strQuery)" fullword
		$s12 = "b = Request.QueryString(\"src\")" fullword
		$s13 = "rw(\"<a href='\" + link + \"' target='\" + target + \"'>\" + title + \"</a>\")" fullword

	condition:
		all of them
}
