import "pe"

rule SIGNATURE_BASE_Aspack_Chinese
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPack Chinese.ini"
		author = "Florian Roth (Nextron Systems)"
		id = "ac821117-7534-5dec-9477-25be87361900"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1769-L1786"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "02a9394bc2ec385876c4b4f61d72471ac8251a8e"
		logic_hash = "98b3af76986cd41190612a2fdfbd9ba48f102456897f4acaedd89a40ab5a582a"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "= Click here if you want to get your registered copy of ASPack" fullword ascii
		$s1 = ";  For beginning of translate - copy english.ini into the yourlanguage.ini" fullword ascii
		$s2 = "E-Mail:                      shinlan@km169.net" fullword ascii
		$s8 = ";  Please, translate text only after simbol '='" fullword ascii
		$s19 = "= Compress with ASPack" fullword ascii

	condition:
		all of them
}
