rule SIGNATURE_BASE_CN_Honker_Webshell_Tuoku_Script_Mssql_2 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mssql.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "3f9706d6-7f6e-5120-945a-d5d928d79507"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L1137-L1153"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ad55512afa109b205e4b1b7968a89df0cf781dc9"
		logic_hash = "1d4b75eeeddda6e92b8ec38679d5e2b9d21abf2d2b467b91a066dcf628725f0a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "sqlpass=request(\"sqlpass\")" fullword ascii
		$s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii
		$s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii

	condition:
		filesize <3KB and all of them
}
