rule SIGNATURE_BASE_FSO_S_Ajan_2
{
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "a66c34ed-0ae2-5e04-bfc4-c82583c5e066"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L9013-L9025"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "22194f8c44524f80254e1b5aec67b03e"
		logic_hash = "0ac31ee735c94289932369dfba5b408cbf71cc23fd48ce3e09dc7ce640a0d733"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
		$s3 = "/file.zip"

	condition:
		all of them
}