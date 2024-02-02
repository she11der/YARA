rule SIGNATURE_BASE_Winx_Shell_Html
{
	meta:
		description = "Semi-Auto-generated  - file WinX Shell.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "fe02d995-4375-5ce9-aabe-fae5d29278d3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3972-L3984"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "17ab5086aef89d4951fe9b7c7a561dda"
		logic_hash = "4248f807d66990946523ba7b92d795c2c40429182389d9bf3f4a972e246b50c6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "WinX Shell"
		$s1 = "Created by greenwood from n57"
		$s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>"

	condition:
		2 of them
}