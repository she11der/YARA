rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Hy2006A : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file hy2006a.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "115651d3-63e1-58e3-b27c-42271111bb91"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L725-L740"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "20da92b2075e6d96636f883dcdd3db4a38c01090"
		logic_hash = "a24bf11a2728bb8d18ea005b057648770956694e0b257d4464ad15ee3e24eda2"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s15 = "Const myCmdDotExeFile = \"command.com\"" fullword ascii
		$s16 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii

	condition:
		filesize <406KB and all of them
}
