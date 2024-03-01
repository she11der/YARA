rule SIGNATURE_BASE_Customize_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Customize.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "1f7e9063-33d8-5df4-89d5-7d8fc1be61f0"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L208-L222"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "37cd17543e14109d3785093e150652032a85d734"
		logic_hash = "aa0940a21eea6ba50a93dd36a8f914f636fdba0685048fc67e16dd68c1c2794e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
		$s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii

	condition:
		filesize <30KB and all of them
}
