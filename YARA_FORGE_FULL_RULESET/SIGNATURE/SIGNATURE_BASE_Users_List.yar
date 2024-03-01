rule SIGNATURE_BASE_Users_List : FILE
{
	meta:
		description = "Chinese Hacktool Set - file users_list.php"
		author = "Florian Roth (Nextron Systems)"
		id = "2d90b593-6b65-502c-aeb0-8f2a3d65afd3"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L69-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6fba1a1a607198ed232405ccbebf9543037a63ef"
		logic_hash = "debd8e1d882cbbe6e720b86bec3ff3c78393cb225b3f0f9c7725cfced6582e71"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
		$s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
		$s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii

	condition:
		filesize <12KB and all of them
}
