import "pe"

rule DITEKSHEN_INDICATOR_TOOL_Atlasreaper : FILE
{
	meta:
		description = "Detects AtlasReaper command-line tool for Confluence and Jira reconnaissance, credential farming and social engineering"
		author = "ditekSHen"
		id = "a0b4e134-bb05-5cc3-af71-516a0407aa1b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L1438-L1453"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4a0436d5c3f1609d23b2b919bebdc56a7fd63e81b99e72dcda1022487cb88240"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$s1 = "/((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})/" fullword wide
		$s2 = "/rest/api/3/search?jql=" fullword wide
		$s3 = "attachments+IS+NOT+EMPTY&fields=attachment,summary,status" fullword wide
		$s4 = "<ParseJira>b__" ascii
		$s5 = "<Atlas_Doc_Format>k__" ascii
		$s6 = "<ParseConfluence>b__" ascii
		$s7 = "AtlasReaper_ProcessedByFody" fullword ascii
		$s8 = /AtlasReaper\.(Jira|Confluence)/ fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
