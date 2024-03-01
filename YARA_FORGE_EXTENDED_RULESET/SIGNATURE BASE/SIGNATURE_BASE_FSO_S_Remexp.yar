rule SIGNATURE_BASE_FSO_S_Remexp
{
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "48a262bf-7f48-5ed9-b043-80e9d563bf21"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7943-L7956"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b69670ecdbb40012c73686cd22696eeb"
		logic_hash = "b9b966a89ab097494d7af90775bf124f1310c77145be67fa57ebdacd0164e3d0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
		$s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
		$s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"

	condition:
		all of them
}
