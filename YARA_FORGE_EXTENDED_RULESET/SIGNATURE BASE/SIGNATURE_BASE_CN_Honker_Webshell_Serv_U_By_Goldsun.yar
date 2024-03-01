rule SIGNATURE_BASE_CN_Honker_Webshell_Serv_U_By_Goldsun : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U_by_Goldsun.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "d8b85c33-b05d-531a-9c0a-a1dddcae0da4"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L636-L653"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d4d7a632af65a961a1dbd0cff80d5a5c2b397e8c"
		logic_hash = "962b2e75c03f716fc039cf26aa238e9a3faf5a7ea8fb3d4da556fa601790055a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii
		$s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
		$s3 = "127.0.0.1:<%=port%>," fullword ascii
		$s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii

	condition:
		filesize <30KB and 2 of them
}
