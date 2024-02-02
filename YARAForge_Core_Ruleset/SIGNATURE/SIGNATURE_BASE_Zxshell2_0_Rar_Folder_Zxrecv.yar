rule SIGNATURE_BASE_Zxshell2_0_Rar_Folder_Zxrecv
{
	meta:
		description = "Webshells Auto-generated - file zxrecv.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9d36541f-dd55-5385-8e2b-598ad78bdf73"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8662-L8679"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "5d3d12a39f41d51341ef4cb7ce69d30f"
		logic_hash = "7eef63e45f6902e4f2d5f854b2794df3101a2ef145e2d627263db429c2b728d7"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "RyFlushBuff"
		$s1 = "teToWideChar^FiYP"
		$s2 = "mdesc+8F D"
		$s3 = "\\von76std"
		$s4 = "5pur+virtul"
		$s5 = "- Kablto io"
		$s6 = "ac#f{lowi8a"

	condition:
		all of them
}