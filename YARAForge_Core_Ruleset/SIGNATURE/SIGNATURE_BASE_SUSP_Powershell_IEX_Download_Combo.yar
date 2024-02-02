rule SIGNATURE_BASE_SUSP_Powershell_IEX_Download_Combo
{
	meta:
		description = "Detects strings found in sample from CN group repo leak in October 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "1dfedcb0-345c-548c-85ac-3c1e78bfd9e2"
		date = "2018-10-04"
		modified = "2023-12-05"
		reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_suspicious_strings.yar#L202-L218"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0a1507859354e0e0d9284befcf777c4d3883496eb96524a246a1df4f3a247aa9"
		score = 65
		quality = 85
		tags = ""
		hash1 = "13297f64a5f4dd9b08922c18ab100d3a3e6fdeab82f60a4653ab975b8ce393d5"

	strings:
		$x1 = "IEX ((new-object net.webclient).download" ascii nocase
		$fp1 = "chocolatey.org"
		$fp2 = "Remote Desktop in the Appveyor"
		$fp3 = "/appveyor/" ascii

	condition:
		$x1 and not 1 of ($fp*)
}