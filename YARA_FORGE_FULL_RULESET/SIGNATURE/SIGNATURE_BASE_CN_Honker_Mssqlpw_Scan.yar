rule SIGNATURE_BASE_CN_Honker_Mssqlpw_Scan : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file mssqlpw scan.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "7dc29d06-e1e7-527f-b9e5-d75f660fd73e"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L362-L377"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e49def9d72bfef09a639ef3f7329083a0b8b151c"
		logic_hash = "eb3bd38ca317f0b10358581fc3dbb8ca81b991b9a4f4f2d256d81a31028411b9"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "response.Write(\"I Get it ! Password is <font color=red>\" & str & \"</font><BR>" ascii
		$s1 = "response.Write \"Done!<br>Process \" & tTime & \" s\"" fullword ascii

	condition:
		filesize <6KB and all of them
}
