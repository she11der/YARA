rule GCTI_Cobaltstrike_Resources__Template_Vbs_V3_3_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		author = "gssincla@google.com"
		id = "62f35d02-1e4e-5651-b575-888ce06b8bdd"
		date = "2022-11-18"
		modified = "2022-11-22"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Template_Vbs_v3_3_to_v4_x.yara#L17-L41"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
		logic_hash = "c9df0e287eb0eacf7c6cfcf3f6d1043ae6f2fdacd3b22bd42ac71f4b0d7226ff"
		score = 75
		quality = 83
		tags = ""

	strings:
		$ea = "Excel.Application" nocase
		$vis = "Visible = False" nocase
		$wsc = "Wscript.Shell" nocase
		$regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
		$regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
		$regwrite = ".RegWrite" nocase
		$dw = "REG_DWORD"
		$code = ".CodeModule.AddFromString"
		$ao = { 41 75 74 6f 5f 4f 70 65 6e }
		$da = ".DisplayAlerts"

	condition:
		all of them
}
