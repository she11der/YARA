import "pe"

rule SIGNATURE_BASE_Vubrute_Vubrute
{
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7ac74c85-465c-5eb5-8e91-004f28cabb75"
		date = "2014-11-22"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1456-L1472"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
		logic_hash = "9dab03b70b249c0c481e3bc98c3196e83da93ea2723674d38baf32469392d52a"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
		$s1 = "http://ubrute.com" fullword ascii
		$s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
		$s14 = "error.txt" fullword ascii

	condition:
		all of them
}
