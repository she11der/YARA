rule SIGNATURE_BASE_User_Function_String
{
	meta:
		description = "Detects user function string from NCSC report"
		author = "NCSC"
		id = "563ac6af-6b37-53c6-ae13-d97e31edb088"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_ncsc_report_04_2018.yar#L54-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		logic_hash = "04821d1d5c12b5a9aca3c5b4be9f7a7d35320ad1503ccbdadebc7710c613a976"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a2 = "e.RandomHashString"
		$a3 = "e.Decode"
		$a4 = "e.Decrypt"
		$a5 = "e.HashStr"
		$a6 = "e.FromB64"

	condition:
		4 of ($a*)
}