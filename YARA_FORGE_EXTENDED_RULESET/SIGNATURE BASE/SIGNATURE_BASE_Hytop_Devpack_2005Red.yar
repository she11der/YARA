rule SIGNATURE_BASE_Hytop_Devpack_2005Red
{
	meta:
		description = "Webshells Auto-generated - file 2005Red.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "963effd9-f31d-5238-9419-b5dd11822e56"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7739-L7752"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d8ccda2214b3f6eabd4502a050eb8fe8"
		logic_hash = "716b6faa8d1216f592d63b658cdd65d7be0226bf746b5fdf1827bdf881562711"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "scrollbar-darkshadow-color:#FF9DBB;"
		$s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"

	condition:
		all of them
}
