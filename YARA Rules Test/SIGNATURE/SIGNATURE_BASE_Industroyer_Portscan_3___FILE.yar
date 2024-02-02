rule SIGNATURE_BASE_Industroyer_Portscan_3___FILE
{
	meta:
		description = "Detects Industroyer related custom port scaner"
		author = "Florian Roth (Nextron Systems)"
		id = "f6675466-d469-562b-9fb6-7b72bce8a726"
		date = "2017-06-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/x81cSy"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_industroyer.yar#L79-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "539a420989c178b3fa26e313d23e9f9c6804aa6dbd2d94f463ae924d46ac2851"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "893e4cca7fe58191d2f6722b383b5e8009d3885b5913dcd2e3577e5a763cdb3f"

	strings:
		$s1 = "!ZBfamily" fullword ascii
		$s2 = ":g/outddomo;" fullword ascii
		$s3 = "GHIJKLMNOTST" fullword ascii
		$d1 = "Error params Arguments!!!" fullword wide
		$d2 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" fullword wide
		$d3 = "Exhample:App.exe -ip= 127.0.0.1-100," fullword wide
		$d4 = "Error IP Range %ls - %ls" fullword wide
		$d5 = "Can't closesocket." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and all of ($s*) or 2 of ($d*))
}