rule SIGNATURE_BASE_Hytop_Apppack_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "67c86d16-a962-5502-8c39-0a6e3dc04031"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8419-L8430"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
		logic_hash = "0de4800291132efca24b40bebcc895d6873110214c8cbf8384317208e0d9db82"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"

	condition:
		all of them
}
