rule SIGNATURE_BASE_Hytop_Devpack_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "963effd9-f31d-5238-9419-b5dd11822e56"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8740-L8753"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
		logic_hash = "b312cddff4c5292cc51acc39448c815fede3c9356d7d225c3a08c7124712b3f8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
		$s8 = "scrollbar-darkshadow-color:#9C9CD3;"
		$s9 = "scrollbar-face-color:#E4E4F3;"

	condition:
		all of them
}
