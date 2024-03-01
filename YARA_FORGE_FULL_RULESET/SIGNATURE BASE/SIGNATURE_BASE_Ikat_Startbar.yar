import "pe"

rule SIGNATURE_BASE_Ikat_Startbar
{
	meta:
		description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f29f15e9-aa29-519a-b4ad-c018aac68fd6"
		date = "2014-05-11"
		modified = "2023-12-05"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L905-L925"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
		logic_hash = "adb29d4903a771b0dab9dee8313878757ff12fc014da86291e32eb3ec60bf551"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Shinysoft Limited1" fullword ascii
		$s3 = "Shinysoft Limited0" fullword ascii
		$s4 = "Wellington1" fullword ascii
		$s6 = "Wainuiomata1" fullword ascii
		$s8 = "56 Wright St1" fullword ascii
		$s9 = "UTN-USERFirst-Object" fullword ascii
		$s10 = "New Zealand1" fullword ascii

	condition:
		all of them
}
