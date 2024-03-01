rule SIGNATURE_BASE_CN_Honker_Webshell_Tuoku_Script_Mysql : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mysql.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "fa0627fb-a40c-5856-ae78-17d33910878f"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L777-L791"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8e242c40aabba48687cfb135b51848af4f2d389d"
		logic_hash = "bde2ea1ccfc88138456a1b255a32a7323f5ef0f677499db6dc6670987cc37585"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii
		$s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii

	condition:
		filesize <202KB and all of them
}
