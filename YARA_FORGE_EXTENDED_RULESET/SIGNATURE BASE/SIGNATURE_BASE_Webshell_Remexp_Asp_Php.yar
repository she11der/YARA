rule SIGNATURE_BASE_Webshell_Remexp_Asp_Php
{
	meta:
		description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "274c8816-2711-5f12-937e-549ec2d57ce1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L5555-L5570"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"
		logic_hash = "b3cfa44898629ffa20630436ae10a94ad72f0e793d61e1157a4de649aa048fe2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
		$s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
		$s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
		$s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
		$s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword

	condition:
		all of them
}
