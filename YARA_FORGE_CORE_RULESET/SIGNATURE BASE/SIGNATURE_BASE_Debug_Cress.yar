rule SIGNATURE_BASE_Debug_Cress
{
	meta:
		description = "Webshells Auto-generated - file cress.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6cf3e43c-bec1-5688-b1d7-8ac48d59153a"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8338-L8350"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "36a416186fe010574c9be68002a7286a"
		logic_hash = "670e236e72d3cb52ea5dba865749baee58a70f8d100db1dd8eddfe3183339181"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\Mithril "
		$s4 = "Mithril.exe"

	condition:
		all of them
}
