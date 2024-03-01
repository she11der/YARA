import "pe"

rule SIGNATURE_BASE_Sig_238_Iecv
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file iecv.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "08126db3-267b-5289-b562-40bc264f6e3e"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2243-L2260"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6e6e75350a33f799039e7a024722cde463328b6d"
		logic_hash = "e2985d85030d88cb63eb8b80673812f85aea6e11c6aeb430387cdb8886958b6a"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Edit The Content Of Cookie " fullword wide
		$s3 = "Accessories\\wordpad.exe" fullword ascii
		$s4 = "gorillanation.com" fullword ascii
		$s5 = "Before editing the content of a cookie, you should close all windows of Internet" ascii
		$s12 = "http://nirsoft.cjb.net" fullword ascii

	condition:
		all of them
}
