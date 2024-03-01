rule SIGNATURE_BASE_Nstview_Nstview
{
	meta:
		description = "Webshells Auto-generated - file nstview.php"
		author = "Florian Roth (Nextron Systems)"
		id = "00df601c-bddb-5da8-bef4-d2122419b5d0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8035-L8046"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "3871888a0c1ac4270104918231029a56"
		logic_hash = "2b25e22d86a672af0b8957f1b0336ed80e09f3389f5045c230af2372db0e3415"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"

	condition:
		all of them
}
