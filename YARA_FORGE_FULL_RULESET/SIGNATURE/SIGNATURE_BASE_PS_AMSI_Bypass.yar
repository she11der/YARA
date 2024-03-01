rule SIGNATURE_BASE_PS_AMSI_Bypass : FILE
{
	meta:
		description = "Detects PowerShell AMSI Bypass"
		author = "Florian Roth (Nextron Systems)"
		id = "31ab8932-4c74-5251-a044-3fcc0aa159f4"
		date = "2017-07-19"
		modified = "2023-12-05"
		reference = "https://gist.github.com/mattifestation/46d6a2ebb4a1f4f0e7229503dc012ef1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_mal_scripts.yar#L4-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "87188c6cbb7d89c25faafb297a7c0e52321c661c84cdefd5604785c687190fcd"
		score = 65
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = ".GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')." ascii nocase

	condition:
		1 of them
}
