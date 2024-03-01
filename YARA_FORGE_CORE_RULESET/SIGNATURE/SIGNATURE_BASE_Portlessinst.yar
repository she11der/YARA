rule SIGNATURE_BASE_Portlessinst
{
	meta:
		description = "Webshells Auto-generated - file portlessinst.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c641c522-7844-5002-8ae7-4aaf60d1337d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8917-L8930"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "74213856fc61475443a91cd84e2a6c2f"
		logic_hash = "72ca80de2ad2048d1fcbbffeebd0e4fd7d9d47d6736360674e6a85ef9943abe8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Fail To Open Registry"
		$s3 = "f<-WLEggDr\""
		$s6 = "oMemoryCreateP"

	condition:
		all of them
}
