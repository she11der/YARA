rule SIGNATURE_BASE_Pwreveal
{
	meta:
		description = "Webshells Auto-generated - file pwreveal.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3d79dd13-9012-56e2-b42a-e6b3e204c601"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8836-L8850"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b4e8447826a45b76ca45ba151a97ad50"
		logic_hash = "01c9582897c65e608d49a151fe9ade97b9a031d7d10f5fd4b4d0c2a3fd83e7b6"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "*<Blank - no es"
		$s3 = "JDiamondCS "
		$s8 = "sword set> [Leith=0 bytes]"
		$s9 = "ION\\System\\Floating-"

	condition:
		all of them
}