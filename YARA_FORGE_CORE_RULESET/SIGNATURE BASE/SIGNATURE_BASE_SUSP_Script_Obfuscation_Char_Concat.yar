rule SIGNATURE_BASE_SUSP_Script_Obfuscation_Char_Concat
{
	meta:
		description = "Detects strings found in sample from CN group repo leak in October 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "6d3bfdfd-ef8f-5740-ac1f-5835c7ce0f43"
		date = "2018-10-04"
		modified = "2023-12-05"
		reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_suspicious_strings.yar#L188-L200"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "28b648e0e1c22fefa49a937f40bd4ed09c5d3894ff059979bad69e8bc98fcac2"
		score = 65
		quality = 85
		tags = ""
		hash1 = "b30cc10e915a23c7273f0838297e0d2c9f4fc0ac1f56100eef6479c9d036c12b"

	strings:
		$s1 = "\"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii

	condition:
		1 of them
}
