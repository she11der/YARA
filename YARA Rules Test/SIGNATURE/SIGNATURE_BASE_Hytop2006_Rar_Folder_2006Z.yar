rule SIGNATURE_BASE_Hytop2006_Rar_Folder_2006Z
{
	meta:
		description = "Webshells Auto-generated - file 2006Z.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7523-L7535"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "fd1b6129abd4ab177fed135e3b665488"
		logic_hash = "4b427132541cd26ee47c387a98f6f46f86808f9a775068e1d114c9ef4abca9f6"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
		$s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"

	condition:
		all of them
}