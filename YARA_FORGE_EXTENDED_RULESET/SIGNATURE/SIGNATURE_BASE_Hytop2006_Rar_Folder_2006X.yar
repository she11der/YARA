rule SIGNATURE_BASE_Hytop2006_Rar_Folder_2006X
{
	meta:
		description = "Webshells Auto-generated - file 2006X.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7887-L7899"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cf3ee0d869dd36e775dfcaa788db8e4b"
		logic_hash = "b71cf90900c7eae4caef57564292ca497a2c6c77e3de2994ba9e4cecae7f2697"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<input name=\"password\" type=\"password\" id=\"password\""
		$s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""

	condition:
		all of them
}
