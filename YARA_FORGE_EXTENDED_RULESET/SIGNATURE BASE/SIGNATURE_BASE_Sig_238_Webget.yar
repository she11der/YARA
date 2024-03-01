import "pe"

rule SIGNATURE_BASE_Sig_238_Webget
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file webget.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b03a2463-94fe-5050-8e3d-269101a03cda"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1733-L1749"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
		logic_hash = "958c465caddf6436b29042f1f1772e039d011d23ff13d91818a9d7ad21a2c750"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "GET A HTTP/1.0" fullword ascii
		$s2 = " error " fullword ascii
		$s13 = "Downloa" ascii

	condition:
		all of them
}
