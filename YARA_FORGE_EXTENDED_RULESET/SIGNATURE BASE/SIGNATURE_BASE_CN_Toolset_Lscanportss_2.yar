import "pe"

rule SIGNATURE_BASE_CN_Toolset_Lscanportss_2
{
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0a796585-5fc8-5b55-acfc-3fe87308b681"
		date = "2015-03-30"
		modified = "2023-12-05"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3008-L3028"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4631ec57756466072d83d49fbc14105e230631a0"
		logic_hash = "aeecdbef3fe6d66a209df10b44046783e53ef12f67c6877309cb219db4354733"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "LScanPort.EXE" fullword wide
		$s3 = "www.honker8.com" fullword wide
		$s4 = "DefaultPort.lst" fullword ascii
		$s5 = "Scan over.Used %dms!" fullword ascii
		$s6 = "www.hf110.com" fullword wide
		$s15 = "LScanPort Microsoft " fullword wide
		$s18 = "L-ScanPort2.0 CooFly" fullword wide

	condition:
		4 of them
}
