rule SIGNATURE_BASE_Fireball_De_Svr : FILE
{
	meta:
		description = "Detects Fireball malware - file de_svr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "29395239-66d8-5340-b884-9b8f036cc27f"
		date = "2017-06-02"
		modified = "2023-12-05"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_fireball.yar#L12-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9ac858b3ce50daac811ded4664f2a602a32d8811825733d235125fc81a488e58"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f964a4b95d5c518fd56f06044af39a146d84b801d9472e022de4c929a5b8fdcc"

	strings:
		$s1 = "cmd.exe /c MD " fullword ascii
		$s2 = "rundll32.exe \"%s\",%s" fullword wide
		$s3 = "http://d12zpbetgs1pco.cloudfront.net/Weatherapi/shell" fullword wide
		$s4 = "C:\\v3\\exe\\de_svr_inst.pdb" fullword ascii
		$s5 = "Internet Connect Failed!" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and 4 of them )
}
