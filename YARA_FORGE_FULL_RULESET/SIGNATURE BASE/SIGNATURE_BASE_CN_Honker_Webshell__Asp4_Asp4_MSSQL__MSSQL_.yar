rule SIGNATURE_BASE_CN_Honker_Webshell__Asp4_Asp4_MSSQL__MSSQL_ : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files asp4.txt, asp4.txt, MSSQL_.asp, MSSQL_.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "e0070f0d-35d0-5024-88e7-e0e04b29f485"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L901-L921"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a8ec5ad87c83c16f47391c3ce08cee74c6be1e42c288eec6d1559867d28489c6"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "4005b83ced1c032dc657283341617c410bc007b8"
		hash1 = "4005b83ced1c032dc657283341617c410bc007b8"
		hash2 = "7097c21f92306983add3b5b29a517204cd6cd819"
		hash3 = "7097c21f92306983add3b5b29a517204cd6cd819"

	strings:
		$s0 = "\"<form name=\"\"searchfileform\"\" action=\"\"?action=searchfile\"\" method=\"" ascii
		$s1 = "\"<TD ALIGN=\"\"Left\"\" colspan=\"\"5\"\">[\"& DbName & \"]" fullword ascii
		$s2 = "Set Conn = Nothing " fullword ascii

	condition:
		filesize <341KB and all of them
}
