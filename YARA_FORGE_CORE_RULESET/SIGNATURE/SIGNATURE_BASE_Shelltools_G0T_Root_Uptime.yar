rule SIGNATURE_BASE_Shelltools_G0T_Root_Uptime
{
	meta:
		description = "Webshells Auto-generated - file uptime.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4f649757-9502-5640-bc17-11cad6c779f4"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7578-L7593"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d1f56102bc5d3e2e37ab3ffa392073b9"
		logic_hash = "5d91dda859a63a965250bd4d76565c6adf18e4ee306be3b91965e5d35bc521e8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "JDiamondCSlC~"
		$s1 = "CharactQA"
		$s2 = "$Info: This file is packed with the UPX executable packer $"
		$s5 = "HandlereateConso"
		$s7 = "ION\\System\\FloatingPo"

	condition:
		all of them
}
