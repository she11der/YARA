rule SIGNATURE_BASE_Stealth_Stealth
{
	meta:
		description = "Auto-generated rule on file Stealth.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "5f45882e-3e27-596d-8725-fad380e1c297"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L435-L446"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
		logic_hash = "e210b1a553549c22f66511dfc9d0d3f5b17f02981b9e9915827bc909f34b3262"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s3 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s6 = "This tool may be used only by system administrators. I am not responsible for "

	condition:
		all of them
}