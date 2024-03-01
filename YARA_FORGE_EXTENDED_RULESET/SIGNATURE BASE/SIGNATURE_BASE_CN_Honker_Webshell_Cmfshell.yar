rule SIGNATURE_BASE_CN_Honker_Webshell_Cmfshell : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file cmfshell.cmf"
		author = "Florian Roth (Nextron Systems)"
		id = "c5670deb-952c-5ba4-949a-097cc09bb108"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L944-L959"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b9b2107c946431e4ad1a8f5e53ac05e132935c0e"
		logic_hash = "f138a82c2d6a831626fe200308eb89cb50ffeec2f2722599eb4ccbd082bad73d"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii
		$s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii

	condition:
		filesize <4KB and all of them
}
