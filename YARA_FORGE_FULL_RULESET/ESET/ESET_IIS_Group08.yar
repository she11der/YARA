import "pe"

rule ESET_IIS_Group08
{
	meta:
		description = "Detects Group 8 native IIS malware family"
		author = "ESET Research"
		id = "d0e9a5ec-b7f0-5d3f-93b4-d048503eb210"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/badiis/badiis.yar#L298-L337"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "d5826d454d25ecbbb5da464da974023a247517d873cf10dc0eafa91e185451da"
		score = 75
		quality = 53
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$i1 = "FliterSecurity.dll"
		$i2 = "IIS7NativeModule.dll"
		$i3 = "Ver1.0."
		$s1 = "Cmd"
		$s2 = "Realy path : %s"
		$s3 = "Logged On Users : %d"
		$s4 = "Connect OK!"
		$s5 = "You are fucked!"
		$s6 = "Shit!Error"
		$s7 = "Where is the God!!"
		$s8 = "Shit!Download False!"
		$s9 = "Good!Run OK!"
		$s10 = "Shit!Run False!"
		$s11 = "Good!Download OK!"
		$s12 = "[%d]safedog"
		$s13 = "ed81bfc09d069121"
		$s14 = "a9478ef01967d190"
		$s15 = "af964b7479e5aea2"
		$s16 = "1f9e6526bea65b59"
		$s17 = "2b9e9de34f782d31"
		$s18 = "33cc5da72ac9d7bb"
		$s19 = "b1d71f4c2596cd55"
		$s20 = "101fb9d9e86d9e6c"

	condition:
		ESET_IIS_Native_Module_PRIVATE and 1 of ($i*) and 3 of ($s*)
}
