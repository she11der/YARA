rule SIGNATURE_BASE_Molerats_Jul17_Sample_4___FILE
{
	meta:
		description = "Detects Molerats sample - July 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "cad0c6a2-d286-52fa-b9b8-793ab9ae048f"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_molerats_jul17.yar#L61-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "dec058ae52a860f4850d7b8024b96c5a9044fdcebadbc12b384f5a6dfae91634"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "512a14130a7a8b5c2548aa488055051ab7e725106ddf2c705f6eb4cfa5dc795c"

	strings:
		$x1 = "get-itemproperty -path 'HKCU:\\SOFTWARE\\Microsoft\\' -name 'KeyName')" wide
		$x2 = "O.Run C & chrw(34) & \"[System.IO.File]::" wide
		$x3 = "HKCU\\SOFTWARE\\Microsoft\\\\KeyName\"" fullword wide

	condition:
		( filesize <700KB and 1 of them )
}