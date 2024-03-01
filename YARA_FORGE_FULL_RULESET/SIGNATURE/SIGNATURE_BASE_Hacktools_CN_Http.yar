import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Http : FILE
{
	meta:
		description = "Disclosed hacktool set - file Http.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bbff6ff6-8cef-5a83-afd3-34f306e8e715"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1340-L1356"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "788bf0fdb2f15e0c628da7056b4e7b1a66340338"
		logic_hash = "690b41bdf856e0d4d90b4a42524134302e9649018fdd495c359582aa6121a017"
		score = 60
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "RPCRT4.DLL" fullword ascii
		$s1 = "WNetAddConnection2A" fullword ascii
		$s2 = "NdrPointerBufferSize" fullword ascii
		$s3 = "_controlfp" fullword ascii

	condition:
		all of them and filesize <10KB
}
