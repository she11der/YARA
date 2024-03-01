import "pe"

rule SIGNATURE_BASE_Ikat_Tools_Nmap
{
	meta:
		description = "Generic rule for NMAP - based on NMAP 4 standalone"
		author = "Florian Roth (Nextron Systems)"
		id = "be4858e6-a8f3-55eb-9c04-f4def838dde1"
		date = "2014-05-11"
		modified = "2023-12-05"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L886-L903"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d0543f365df61e6ebb5e345943577cc40fca8682"
		logic_hash = "f538d807ed4904a2c321385a095a97bc0d718349f7eb31a367e521228412cef2"
		score = 50
		quality = 83
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Insecure.Org" fullword wide
		$s1 = "Copyright (c) Insecure.Com" fullword wide
		$s2 = "nmap" fullword nocase
		$s3 = "Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm)." ascii

	condition:
		all of them
}
