rule SIGNATURE_BASE_FSO_S_Indexer
{
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "fba053d7-5413-563f-8c27-0554349500b2"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7702-L7713"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "135fc50f85228691b401848caef3be9e"
		logic_hash = "a1bfba9c24819f5c1574aa179d853a6cc2fcf58c7b9a14eeab2639248178549c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"

	condition:
		all of them
}