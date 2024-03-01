rule SIGNATURE_BASE_Zxshell2_0_Rar_Folder_Zxshell
{
	meta:
		description = "Webshells Auto-generated - file ZXshell.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "621ac87e-b1f8-58d7-9328-54af5ca9b605"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7188-L7200"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "246ce44502d2f6002d720d350e26c288"
		logic_hash = "72eaf90551144eccb7329e0a0e05bcc955ea2bfdb37aa87e9cae7b5f5a26bea0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "WPreviewPagesn"
		$s1 = "DA!OLUTELY N"

	condition:
		all of them
}
