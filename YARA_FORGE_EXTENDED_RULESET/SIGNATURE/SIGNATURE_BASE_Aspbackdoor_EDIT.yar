import "pe"

rule SIGNATURE_BASE_Aspbackdoor_EDIT
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
		author = "Florian Roth (Nextron Systems)"
		id = "cdcec370-97af-51c0-b81a-35a788f16ef4"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2495-L2514"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "12196cf62931cde7b6cb979c07bb5cc6a7535cbb"
		logic_hash = "0f97c831eb9f257a2a6c9a677dde2ce17d529584fb7085bc94edd83d886e469f"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<meta HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=gb_2312-80\">" fullword ascii
		$s2 = "Set thisfile = fs.GetFile(whichfile)" fullword ascii
		$s3 = "response.write \"<a href='index.asp'>" fullword ascii
		$s5 = "if Request.Cookies(\"password\")=\"juchen\" then " fullword ascii
		$s6 = "Set thisfile = fs.OpenTextFile(whichfile, 1, False)" fullword ascii
		$s7 = "color: rgb(255,0,0); text-decoration: underline }" fullword ascii
		$s13 = "if Request(\"creat\")<>\"yes\" then" fullword ascii

	condition:
		5 of them
}
