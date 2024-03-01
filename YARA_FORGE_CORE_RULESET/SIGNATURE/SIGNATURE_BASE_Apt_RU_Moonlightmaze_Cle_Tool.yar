rule SIGNATURE_BASE_Apt_RU_Moonlightmaze_Cle_Tool
{
	meta:
		description = "Rule to detect Moonlight Maze 'cle' log cleaning tool"
		author = "Kaspersky Lab"
		id = "99ae07b9-eb42-53dc-bd8b-75ab6a0b8cab"
		date = "2017-03-27"
		modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_moonlightmaze.yar#L140-L167"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "647d7b711f7b4434145ea30d0ef207b0"
		logic_hash = "a4bbd7be617b944a656fa58ca9ec6384f624c95250de6b8a6ba63e7c3387484c"
		score = 75
		quality = 85
		tags = ""
		version = "1.0"

	strings:
		$a1 = "./a filename template_file" ascii wide
		$a2 = "May be %s is empty?" ascii wide
		$a3 = "template string = |%s|" ascii wide
		$a4 = "No blocks !!!"
		$a5 = "No data in this block !!!!!!" ascii wide
		$a6 = "No good line"

	condition:
		((3 of ($a*)))
}
