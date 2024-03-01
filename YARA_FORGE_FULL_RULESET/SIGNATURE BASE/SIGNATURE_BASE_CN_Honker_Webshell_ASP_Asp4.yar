rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Asp4 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp4.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "4125bb40-3f5c-53f5-b906-54fa77b119f5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L582-L598"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4005b83ced1c032dc657283341617c410bc007b8"
		logic_hash = "ae02d1efc975a8592a00cbab823355fb778fbb589f5752dd913aa432b316c3a4"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
		$s6 = "Response.Cookies(Cookie_Login) = sPwd" fullword ascii
		$s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii

	condition:
		filesize <150KB and all of them
}
