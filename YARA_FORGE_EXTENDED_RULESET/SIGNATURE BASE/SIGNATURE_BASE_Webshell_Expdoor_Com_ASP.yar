rule SIGNATURE_BASE_Webshell_Expdoor_Com_ASP
{
	meta:
		description = "Web shells - generated from file Expdoor.com ASP.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3250-L3267"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "caef01bb8906d909f24d1fa109ea18a7"
		logic_hash = "838edb9d718b5e1a8be155c4569b4a291b37337e71b435c2b1cd6bcaa53c0dea"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "\">www.Expdoor.com</a>" fullword
		$s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
		$s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
		$s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
		$s16 = "<TITLE>Expdoor.com ASP" fullword

	condition:
		2 of them
}
