rule SIGNATURE_BASE_Mithril_V1_45_Mithril
{
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3c160017-0332-532a-bb7f-390a4a34dc4e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7635-L7647"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f1484f882dc381dde6eaa0b80ef64a07"
		logic_hash = "a3e74bfb34762553eccaddd745d9e17dc3a5a25201e4bc9e2ea9a49342295c78"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "cress.exe"
		$s7 = "\\Debug\\Mithril."

	condition:
		all of them
}
