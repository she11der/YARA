rule SIGNATURE_BASE_Adjustcr
{
	meta:
		description = "Webshells Auto-generated - file adjustcr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4b3d9409-60e8-502a-b37b-1e06d57c9b0b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8392-L8406"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "17037fa684ef4c90a25ec5674dac2eb6"
		logic_hash = "d2a86083ff5cb34a0453f812e2d316c63342e529f00099a8869fa7e0a43321ef"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$Info: This file is packed with the UPX executable packer $"
		$s2 = "$License: NRV for UPX is distributed under special license $"
		$s6 = "AdjustCR Carr"
		$s7 = "ION\\System\\FloatingPo"

	condition:
		all of them
}
